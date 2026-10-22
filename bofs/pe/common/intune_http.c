/*
 * Shared WinHTTP request helper for Intune API calls.
 * Merges exchange's http_get and apps' http_request into one function.
 */
#include "beacon.h"
#include "bofdefs_pe.h"
#include "intune_http.h"

#define MAX_RESPONSE (4 * 1024 * 1024)
#define MAX_URL      4096
#define MAX_HEADER   8192

char *http_request(const char *method, const char *url, const char *token,
                   const char *body, int fullmetadata,
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
    wchar_t wpath[MAX_URL] = {0};
    wchar_t wextra[1024] = {0};
    bof_memset(&uc, 0, sizeof(uc));
    uc.dwStructSize = sizeof(uc);
    uc.lpszHostName = whost;
    uc.dwHostNameLength = 255;
    uc.lpszUrlPath = wpath;
    uc.dwUrlPathLength = MAX_URL - 1;
    uc.lpszExtraInfo = wextra;
    uc.dwExtraInfoLength = 1023;

    if (!bof_WinHttpCrackUrl(wurl, 0, 0, &uc)) {
        bof_free(wurl);
        return NULL;
    }
    bof_free(wurl);

    if (wextra[0])
        bof_wcscat(wpath, wextra);

    wchar_t wmethod[16] = {0};
    bof_MultiByteToWideChar(CP_UTF8, 0, method, -1, wmethod, 15);

    HINTERNET hSession = bof_WinHttpOpen(L"IntuneClient/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    if (!hSession)
        return NULL;

    HINTERNET hConnect = bof_WinHttpConnect(hSession, whost, uc.nPort, 0);
    if (!hConnect) {
        bof_WinHttpCloseHandle(hSession);
        return NULL;
    }

    DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = bof_WinHttpOpenRequest(hConnect, wmethod, wpath,
        NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        bof_WinHttpCloseHandle(hConnect);
        bof_WinHttpCloseHandle(hSession);
        return NULL;
    }

    if (client_cert)
        bof_WinHttpSetOption(hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
            (LPVOID)client_cert, sizeof(CERT_CONTEXT));

    wchar_t hdrs[MAX_HEADER];
    if (fullmetadata)
        bof_snwprintf(hdrs, MAX_HEADER,
            L"Authorization: Bearer %S\r\n"
            L"Accept: application/json; odata=fullmetadata\r\n"
            L"Accept-Language: en-US\r\n",
            token);
    else
        bof_snwprintf(hdrs, MAX_HEADER,
            L"Authorization: Bearer %S\r\n"
            L"Accept: application/json\r\n"
            L"Content-Type: application/json\r\n"
            L"Accept-Language: en-US\r\n",
            token);
    hdrs[MAX_HEADER - 1] = L'\0';

    bof_WinHttpAddRequestHeaders(hRequest, hdrs, -1, WINHTTP_ADDREQ_FLAG_ADD);

    DWORD body_len = body ? (DWORD)bof_strlen(body) : 0;
    BOOL send_ok = bof_WinHttpSendRequest(hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        body_len ? (LPVOID)body : WINHTTP_NO_REQUEST_DATA,
        body_len, body_len, 0);

    if (!send_ok && bof_GetLastError() == 12044) {
        if (client_cert)
            bof_WinHttpSetOption(hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                (LPVOID)client_cert, sizeof(CERT_CONTEXT));
        else
            bof_WinHttpSetOption(hRequest, WINHTTP_OPTION_CLIENT_CERT_CONTEXT,
                NULL, 0);
        send_ok = bof_WinHttpSendRequest(hRequest,
            WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            body_len ? (LPVOID)body : WINHTTP_NO_REQUEST_DATA,
            body_len, body_len, 0);
    }

    if (!send_ok || !bof_WinHttpReceiveResponse(hRequest, NULL)) {
        bof_WinHttpCloseHandle(hRequest);
        bof_WinHttpCloseHandle(hConnect);
        bof_WinHttpCloseHandle(hSession);
        return NULL;
    }

    if (out_status) {
        DWORD status = 0, sz = sizeof(status);
        bof_WinHttpQueryHeaders(hRequest,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            NULL, &status, &sz, NULL);
        *out_status = (int)status;
    }

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
        rd = 0;
        if (!bof_WinHttpReadData(hRequest, resp + total, avail, &rd))
            break;
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
