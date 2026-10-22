/*
 * Shared Intune host and device ID discovery.
 * Extracted from exchange.c and apps.c to eliminate duplication.
 */
#include "beacon.h"
#include "bofdefs_pe.h"
#include "intune_discovery.h"

static BOOL is_host_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '-';
}

int find_manage_host(const char *buf, DWORD len, const char *prefix,
                     char *out, int outsz)
{
    const char *suffix = ".manage.microsoft.com";
    DWORD sfxlen = (DWORD)bof_strlen(suffix);
    DWORD i;

    for (i = 0; i + sfxlen <= len; i++) {
        if (bof_strnicmp(buf + i, suffix, sfxlen) != 0)
            continue;

        int start = (int)i - 1;
        while (start >= 0 && is_host_char(buf[start]))
            start--;
        start++;

        if (start >= (int)i)
            continue;

        int dots = 0;
        int k;
        for (k = start; k < (int)i; k++) {
            if (buf[k] == '.')
                dots++;
        }
        if (dots < 1)
            continue;

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

int derive_fef_host(const char *host, char *out, int outsz)
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

int discover_host(char *out, int outsz, const char *prefix)
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

int discover_device_id(char *out, int outsz)
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

    if (pCert)
        bof_CertFreeCertificateContext(pCert);
    bof_CertCloseStore(hStore, 0);
    return found;
}
