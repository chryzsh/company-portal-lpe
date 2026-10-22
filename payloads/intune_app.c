/*
 * intune_app.c - Intune Company Portal app install/uninstall via REST API.
 * Takes a pre-obtained enrollment token and IWService URL.
 * Use askWAM BOF to get the tokens, then pass them here.
 *
 * Cross-compile:
 *   x86_64-w64-mingw32-gcc -o intune_app.exe intune_app.c -lwinhttp
 *   i686-w64-mingw32-gcc -o intune_app_x86.exe intune_app.c -lwinhttp
 */

#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "winhttp.lib")

#define MAX_RESPONSE (4 * 1024 * 1024)
#define MAX_URL 4096
#define MAX_HEADER 8192

static const char *SERVICE_PARAMS =
    "api-version=9.0&ssp=WindowsSSP&ssp-version=11.2.1753.0"
    "&os=Windows&os-version=10.0.26100.0&os-sub=None&arch=x64&mgmt-agent=Mdm";

typedef struct {
    const char *token;
    const char *iwurl;
    const char *device_id;
    int verbose;
} Ctx;

/* ----------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------- */

static wchar_t *to_wide(const char *s) {
    int len = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    wchar_t *w = (wchar_t *)malloc(len * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, len);
    return w;
}

static char *to_utf8(const wchar_t *w) {
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, NULL, 0, NULL, NULL);
    char *s = (char *)malloc(len);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s, len, NULL, NULL);
    return s;
}

/* Build full URL with service params appended */
static void build_url(char *out, size_t outsz, const char *base, const char *extra_params) {
    const char *sep = strchr(base, '?') ? "&" : "?";
    if (extra_params && extra_params[0])
        snprintf(out, outsz, "%s%s%s&%s", base, sep, SERVICE_PARAMS, extra_params);
    else
        snprintf(out, outsz, "%s%s%s", base, sep, SERVICE_PARAMS);
}

/* ----------------------------------------------------------------
 * WinHTTP request
 * ---------------------------------------------------------------- */

static char *http_request(const char *method, const char *url,
                          const char *token, const char *body,
                          int fullmetadata, int *out_status) {
    wchar_t *wurl = to_wide(url);
    URL_COMPONENTSW uc;
    wchar_t host[256] = {0}, path[MAX_URL] = {0};
    memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = host;
    uc.dwHostNameLength = 255;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = MAX_URL - 1;

    if (!WinHttpCrackUrl(wurl, 0, 0, &uc)) {
        fprintf(stderr, "[-] WinHttpCrackUrl failed: %lu\n", GetLastError());
        free(wurl);
        return NULL;
    }

    HINTERNET hSession = WinHttpOpen(L"IntuneApp/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession) { free(wurl); return NULL; }

    HINTERNET hConnect = WinHttpConnect(hSession, host, uc.nPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); free(wurl); return NULL; }

    wchar_t *wmethod = to_wide(method);
    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, wmethod, path,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    free(wmethod);
    free(wurl);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return NULL; }

    /* Headers */
    char hdr_buf[MAX_HEADER];
    if (fullmetadata)
        snprintf(hdr_buf, sizeof(hdr_buf),
            "Authorization: Bearer %s\r\n"
            "Accept: application/json; odata=fullmetadata\r\n"
            "Accept-Language: en-US\r\n",
            token);
    else
        snprintf(hdr_buf, sizeof(hdr_buf),
            "Authorization: Bearer %s\r\n"
            "Content-Type: application/json\r\n"
            "Accept-Language: en-US\r\n",
            token);

    wchar_t *whdrs = to_wide(hdr_buf);
    WinHttpAddRequestHeaders(hRequest, whdrs, -1, WINHTTP_ADDREQ_FLAG_ADD);
    free(whdrs);

    /* Send */
    DWORD body_len = body ? (DWORD)strlen(body) : 0;
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            body ? (LPVOID)body : WINHTTP_NO_REQUEST_DATA, body_len, body_len, 0)) {
        fprintf(stderr, "[-] WinHttpSendRequest failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        fprintf(stderr, "[-] WinHttpReceiveResponse failed: %lu\n", GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    /* Status code */
    DWORD status = 0, sz = sizeof(status);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        NULL, &status, &sz, NULL);
    if (out_status) *out_status = (int)status;

    /* Read response body */
    char *resp = (char *)malloc(MAX_RESPONSE);
    DWORD total = 0, avail, rd;
    while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
        if (total + avail >= (DWORD)MAX_RESPONSE - 1) avail = MAX_RESPONSE - 1 - total;
        WinHttpReadData(hRequest, resp + total, avail, &rd);
        total += rd;
        if (total >= (DWORD)MAX_RESPONSE - 1) break;
    }
    resp[total] = '\0';

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

/* ----------------------------------------------------------------
 * Minimal JSON helpers (string scanning, no parser)
 * ---------------------------------------------------------------- */

/* Find "key":"value" and return pointer to value start, set *len */
static const char *json_find_string(const char *json, const char *key, int *len) {
    char pattern[256];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *p = json;
    while ((p = strstr(p, pattern)) != NULL) {
        p += strlen(pattern);
        /* skip whitespace and colon */
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == ':') p++;
        if (*p == '"') {
            p++;
            const char *start = p;
            while (*p && !(*p == '"' && *(p-1) != '\\')) p++;
            if (len) *len = (int)(p - start);
            return start;
        }
    }
    return NULL;
}

/* Extract a JSON string value, caller frees */
static char *json_get_string(const char *json, const char *key) {
    int len = 0;
    const char *val = json_find_string(json, key, &len);
    if (!val || len <= 0) return NULL;
    char *out = (char *)malloc(len + 1);
    memcpy(out, val, len);
    out[len] = '\0';
    return out;
}

/* Find an OData action target: "#Install":{"target":"https://..."} */
static char *find_odata_action(const char *json, const char *action) {
    char patterns[4][256];
    snprintf(patterns[0], 256, "\"#CommonContainer.%s\"", action);
    snprintf(patterns[1], 256, "\"#%s\"", action);
    snprintf(patterns[2], 256, "\"%s\"", action);
    snprintf(patterns[3], 256, "\"#Microsoft.Services.SystemCenter.IWService.Common.%s\"", action);

    for (int i = 0; i < 4; i++) {
        const char *p = strstr(json, patterns[i]);
        if (!p) continue;
        p += strlen(patterns[i]);
        /* Find "target" within next 300 chars */
        const char *limit = p + 300;
        if (limit > json + strlen(json)) limit = json + strlen(json);

        const char *t = p;
        while (t < limit && (t = strstr(t, "\"target\"")) != NULL && t < limit) {
            int tlen = 0;
            const char *tv = json_find_string(t - 1, "target", &tlen);
            if (tv && tlen > 0) {
                char *out = (char *)malloc(tlen + 1);
                memcpy(out, tv, tlen);
                out[tlen] = '\0';
                return out;
            }
            t++;
        }
    }
    return NULL;
}

/* Iterate JSON array: find each {...} block in "value":[...] */
typedef int (*array_cb)(const char *obj, int obj_len, void *ctx);

static int json_foreach_value(const char *json, array_cb cb, void *ctx) {
    const char *arr = strstr(json, "\"value\"");
    if (!arr) return 0;
    arr = strchr(arr, '[');
    if (!arr) return 0;
    arr++;

    int count = 0;
    while (*arr) {
        while (*arr == ' ' || *arr == '\t' || *arr == '\n' || *arr == '\r' || *arr == ',') arr++;
        if (*arr == ']') break;
        if (*arr != '{') break;

        /* Find matching } with nesting */
        int depth = 0;
        const char *start = arr;
        while (*arr) {
            if (*arr == '{') depth++;
            else if (*arr == '}') { depth--; if (depth == 0) { arr++; break; } }
            else if (*arr == '"') { arr++; while (*arr && *arr != '"') { if (*arr == '\\') arr++; arr++; } }
            arr++;
        }

        int obj_len = (int)(arr - start);
        char *obj = (char *)malloc(obj_len + 1);
        memcpy(obj, start, obj_len);
        obj[obj_len] = '\0';

        int ret = cb(obj, obj_len, ctx);
        free(obj);
        count++;
        if (ret < 0) break;
    }
    return count;
}

/* ----------------------------------------------------------------
 * Commands
 * ---------------------------------------------------------------- */

typedef struct {
    int idx;
    Ctx *ctx;
} ListCtx;

static int list_app_cb(const char *obj, int obj_len, void *data) {
    ListCtx *lc = (ListCtx *)data;
    lc->idx++;
    char *name = json_get_string(obj, "Name");
    char *guid = json_get_string(obj, "GuidKey");
    char *pub = json_get_string(obj, "Publisher");
    char *nav = json_get_string(obj, "ApplicationState@odata.navigationLinkUrl");

    printf("  %-3d %-38s %-30s %s\n",
        lc->idx,
        guid ? guid : "?",
        name ? name : "?",
        pub ? pub : "");

    if (lc->ctx->verbose && nav)
        printf("      nav: %s\n", nav);

    free(name); free(guid); free(pub); free(nav);
    return 0;
}

static int cmd_list(Ctx *ctx) {
    char url[MAX_URL];
    char base[MAX_URL];
    snprintf(base, sizeof(base), "%s/Applications?$top=100", ctx->iwurl);

    char extra[256] = {0};
    if (ctx->device_id)
        snprintf(extra, sizeof(extra), "device-id=%s", ctx->device_id);
    build_url(url, sizeof(url), base, extra);

    printf("[*] GET %s\n", ctx->verbose ? url : "Applications");

    int status = 0;
    char *resp = http_request("GET", url, ctx->token, NULL, 1, &status);
    if (!resp) { fprintf(stderr, "[-] Request failed\n"); return 1; }

    if (status != 200) {
        fprintf(stderr, "[-] HTTP %d\n", status);
        if (ctx->verbose) fprintf(stderr, "%.*s\n", 500, resp);
        free(resp);
        return 1;
    }

    printf("[*] Applications:\n\n");
    printf("  %-3s %-38s %-30s %s\n", "#", "AppId", "Name", "Publisher");
    printf("  %s\n", "--------------------------------------------------------------------------");

    ListCtx lc = { 0, ctx };
    int n = json_foreach_value(resp, list_app_cb, &lc);
    printf("\n[*] %d app(s)\n", n);

    free(resp);
    return 0;
}

/* Get the ApplicationState nav link for a specific app */
static char *get_app_nav_link(Ctx *ctx, const char *app_guid) {
    char url[MAX_URL];
    char base[MAX_URL];
    snprintf(base, sizeof(base), "%s/Applications?$top=100", ctx->iwurl);

    char extra[256] = {0};
    if (ctx->device_id)
        snprintf(extra, sizeof(extra), "device-id=%s", ctx->device_id);
    build_url(url, sizeof(url), base, extra);

    int status = 0;
    char *resp = http_request("GET", url, ctx->token, NULL, 1, &status);
    if (!resp || status != 200) { free(resp); return NULL; }

    /* Find the app by GuidKey and get its nav link */
    const char *arr = strstr(resp, "\"value\"");
    if (!arr) { free(resp); return NULL; }
    arr = strchr(arr, '[');
    if (!arr) { free(resp); return NULL; }

    /* Scan through objects */
    const char *search = arr;
    char *nav_link = NULL;
    char guid_pattern[128];
    snprintf(guid_pattern, sizeof(guid_pattern), "\"%s\"", app_guid);

    while (1) {
        const char *obj_start = strchr(search, '{');
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

        char *obj = (char *)malloc(obj_len + 1);
        memcpy(obj, obj_start, obj_len);
        obj[obj_len] = '\0';

        char *gk = json_get_string(obj, "GuidKey");
        if (gk && _stricmp(gk, app_guid) == 0) {
            nav_link = json_get_string(obj, "ApplicationState@odata.navigationLinkUrl");
            free(gk);
            free(obj);
            break;
        }
        free(gk);
        free(obj);
        search = p;
    }

    free(resp);
    return nav_link;
}

/* Fetch the action target URL (Install or Uninstall) for an app */
static char *get_action_target(Ctx *ctx, const char *app_guid, const char *action) {
    printf("[*] Looking up %s action for %s...\n", action, app_guid);

    char *nav_link = get_app_nav_link(ctx, app_guid);
    if (!nav_link) {
        fprintf(stderr, "[-] App not found or no navigation link: %s\n", app_guid);
        return NULL;
    }

    /* Make the nav link absolute */
    char abs_url[MAX_URL];
    if (strncmp(nav_link, "http", 4) != 0)
        snprintf(abs_url, sizeof(abs_url), "%s/%s", ctx->iwurl, nav_link);
    else
        snprintf(abs_url, sizeof(abs_url), "%s", nav_link);
    free(nav_link);

    /* Add device-id filter */
    char url[MAX_URL];
    char extra[512] = {0};
    if (ctx->device_id)
        snprintf(extra, sizeof(extra), "$filter=DeviceId%%20eq%%20guid'%s'&device-id=%s",
            ctx->device_id, ctx->device_id);
    build_url(url, sizeof(url), abs_url, extra);

    if (ctx->verbose) printf("[*] GET %s\n", url);

    int status = 0;
    char *resp = http_request("GET", url, ctx->token, NULL, 1, &status);
    if (!resp || status != 200) {
        fprintf(stderr, "[-] ApplicationState request failed (HTTP %d)\n", status);
        free(resp);
        return NULL;
    }

    /* Find the right app state in the response */
    char *target = NULL;
    const char *arr = strstr(resp, "\"value\"");
    if (arr) {
        arr = strchr(arr, '[');
        if (arr) {
            /* Search through state objects for our app */
            const char *search = arr;
            while (1) {
                const char *obj_start = strchr(search, '{');
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

                char *obj = (char *)malloc(obj_len + 1);
                memcpy(obj, obj_start, obj_len);
                obj[obj_len] = '\0';

                char *app_id = json_get_string(obj, "ApplicationId");
                if (app_id && _stricmp(app_id, app_guid) == 0) {
                    target = find_odata_action(obj, action);
                    char *cs = json_get_string(obj, "CombinedStatus");
                    if (cs) {
                        printf("[*] App status: %s\n", cs);
                        free(cs);
                    }
                }
                free(app_id);
                free(obj);
                if (target) break;
                search = p;
            }
        }
    }

    free(resp);
    return target;
}

static int cmd_action(Ctx *ctx, const char *app_guid, const char *action) {
    char *target = get_action_target(ctx, app_guid, action);
    if (!target) {
        fprintf(stderr, "[-] No %s action available for %s\n", action, app_guid);
        return 1;
    }

    printf("[*] %s target: %s\n", action, ctx->verbose ? target : "(found)");

    /* POST to the action target */
    char url[MAX_URL];
    char extra[256] = {0};
    if (ctx->device_id)
        snprintf(extra, sizeof(extra), "device-id=%s", ctx->device_id);
    build_url(url, sizeof(url), target, extra);

    if (ctx->verbose) printf("[*] POST %s\n", url);

    int status = 0;
    char *resp = http_request("POST", url, ctx->token, "", 0, &status);

    if (status >= 200 && status < 300) {
        printf("[+] %s succeeded (HTTP %d)\n", action, status);
    } else {
        fprintf(stderr, "[-] %s failed (HTTP %d)\n", action, status);
        if (resp && ctx->verbose) fprintf(stderr, "%.*s\n", 500, resp);
    }

    free(target);
    free(resp);
    return (status >= 200 && status < 300) ? 0 : 1;
}

/* ----------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------- */

static void usage(void) {
    printf("IntuneApp - Intune Company Portal app management via REST API\n\n");
    printf("Usage:\n");
    printf("  IntuneApp.exe --token <enrollment_token> --url <iwservice_url> [options] <command>\n\n");
    printf("Options:\n");
    printf("  --token <token>     Enrollment token (from askWAM + token exchange)\n");
    printf("  --url <url>         IWService endpoint URL\n");
    printf("  --device-id <guid>  Intune device ID (from MDM cert CN)\n");
    printf("  -v                  Verbose output\n\n");
    printf("Commands:\n");
    printf("  list                          List available applications\n");
    printf("  install <app_guid>            Install an application\n");
    printf("  uninstall <app_guid>          Uninstall an application\n");
}

int main(int argc, char *argv[]) {
    Ctx ctx = {0};
    const char *command = NULL;
    const char *app_guid = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--token") == 0 && i + 1 < argc)
            ctx.token = argv[++i];
        else if (strcmp(argv[i], "--url") == 0 && i + 1 < argc)
            ctx.iwurl = argv[++i];
        else if (strcmp(argv[i], "--device-id") == 0 && i + 1 < argc)
            ctx.device_id = argv[++i];
        else if (strcmp(argv[i], "-v") == 0)
            ctx.verbose = 1;
        else if (!command)
            command = argv[i];
        else if (!app_guid)
            app_guid = argv[i];
    }

    if (!ctx.token || !ctx.iwurl || !command) {
        usage();
        return 1;
    }

    /* Strip trailing slash from URL */
    size_t ulen = strlen(ctx.iwurl);
    char *url_buf = (char *)malloc(ulen + 1);
    strcpy(url_buf, ctx.iwurl);
    while (ulen > 0 && url_buf[ulen - 1] == '/') url_buf[--ulen] = '\0';
    ctx.iwurl = url_buf;

    int ret = 1;
    if (_stricmp(command, "list") == 0) {
        ret = cmd_list(&ctx);
    } else if (_stricmp(command, "install") == 0) {
        if (!app_guid) { fprintf(stderr, "Usage: install <app_guid>\n"); goto done; }
        ret = cmd_action(&ctx, app_guid, "Install");
    } else if (_stricmp(command, "uninstall") == 0) {
        if (!app_guid) { fprintf(stderr, "Usage: uninstall <app_guid>\n"); goto done; }
        ret = cmd_action(&ctx, app_guid, "Uninstall");
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        usage();
    }

done:
    free(url_buf);
    return ret;
}
