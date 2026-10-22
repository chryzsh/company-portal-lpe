/*
 * BOF Dynamic Function Resolution (DFR) Definitions
 * For the Company Portal exploit chain BOFs (exchange, apps, race).
 */
#ifndef _BOFDEFS_H_
#define _BOFDEFS_H_

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>

/* ================================================================
 * KERNEL32
 * ================================================================ */
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapReAlloc(HANDLE, DWORD, LPVOID, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
DECLSPEC_IMPORT void    WINAPI KERNEL32$SetLastError(DWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WriteFile(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FlushFileBuffers(HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT void    WINAPI KERNEL32$Sleep(DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CreateDirectoryW(LPCWSTR, LPSECURITY_ATTRIBUTES);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadDirectoryChangesW(HANDLE, LPVOID, DWORD, BOOL, DWORD, LPDWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateEventW(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCWSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$GetOverlappedResult(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetTickCount(void);
DECLSPEC_IMPORT void    WINAPI KERNEL32$RtlZeroMemory(PVOID, SIZE_T);
DECLSPEC_IMPORT int     WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT LPWSTR  WINAPI KERNEL32$lstrcpyW(LPWSTR, LPCWSTR);
DECLSPEC_IMPORT int     WINAPI KERNEL32$lstrcmpiW(LPCWSTR, LPCWSTR);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$OpenFileMappingW(DWORD, BOOL, LPCWSTR);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$MapViewOfFile(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$UnmapViewOfFile(LPCVOID);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$SetNamedPipeHandleState(HANDLE, LPDWORD, LPDWORD, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$WaitNamedPipeW(LPCWSTR, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CancelIo(HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetCurrentProcessId(void);

/* ================================================================
 * MSVCRT (C runtime via DFR)
 * ================================================================ */
DECLSPEC_IMPORT void *  MSVCRT$malloc(size_t);
DECLSPEC_IMPORT void    MSVCRT$free(void *);
DECLSPEC_IMPORT void *  MSVCRT$realloc(void *, size_t);
DECLSPEC_IMPORT void *  MSVCRT$memcpy(void *, const void *, size_t);
DECLSPEC_IMPORT void *  MSVCRT$memset(void *, int, size_t);
DECLSPEC_IMPORT int     MSVCRT$memcmp(const void *, const void *, size_t);
DECLSPEC_IMPORT size_t  MSVCRT$strlen(const char *);
DECLSPEC_IMPORT size_t  MSVCRT$wcslen(const wchar_t *);
DECLSPEC_IMPORT char *  MSVCRT$strstr(const char *, const char *);
DECLSPEC_IMPORT wchar_t *MSVCRT$wcsstr(const wchar_t *, const wchar_t *);
DECLSPEC_IMPORT int     MSVCRT$strcmp(const char *, const char *);
DECLSPEC_IMPORT int     MSVCRT$_stricmp(const char *, const char *);
DECLSPEC_IMPORT int     MSVCRT$_wcsicmp(const wchar_t *, const wchar_t *);
DECLSPEC_IMPORT int     MSVCRT$strncmp(const char *, const char *, size_t);
DECLSPEC_IMPORT int     MSVCRT$_strnicmp(const char *, const char *, size_t);
DECLSPEC_IMPORT int     MSVCRT$_wcsnicmp(const wchar_t *, const wchar_t *, size_t);
DECLSPEC_IMPORT char *  MSVCRT$strchr(const char *, int);
DECLSPEC_IMPORT wchar_t *MSVCRT$wcschr(const wchar_t *, wchar_t);
DECLSPEC_IMPORT char *  MSVCRT$strncpy(char *, const char *, size_t);
DECLSPEC_IMPORT wchar_t *MSVCRT$wcsncpy(wchar_t *, const wchar_t *, size_t);
DECLSPEC_IMPORT char *  MSVCRT$strcpy(char *, const char *);
DECLSPEC_IMPORT wchar_t *MSVCRT$wcscpy(wchar_t *, const wchar_t *);
DECLSPEC_IMPORT int     MSVCRT$sprintf(char *, const char *, ...);
DECLSPEC_IMPORT int     MSVCRT$_snprintf(char *, size_t, const char *, ...);
DECLSPEC_IMPORT int     MSVCRT$swprintf(wchar_t *, const wchar_t *, ...);
DECLSPEC_IMPORT int     MSVCRT$_snwprintf(wchar_t *, size_t, const wchar_t *, ...);
DECLSPEC_IMPORT int     MSVCRT$atoi(const char *);
DECLSPEC_IMPORT wchar_t *MSVCRT$wcscat(wchar_t *, const wchar_t *);
DECLSPEC_IMPORT char *  MSVCRT$strcat(char *, const char *);

/* ================================================================
 * WINHTTP
 * ================================================================ */
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpen(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpConnect(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
DECLSPEC_IMPORT HINTERNET WINAPI WINHTTP$WinHttpOpenRequest(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR *, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpAddRequestHeaders(HINTERNET, LPCWSTR, DWORD, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpSendRequest(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpReceiveResponse(HINTERNET, LPVOID);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpQueryDataAvailable(HINTERNET, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpReadData(HINTERNET, LPVOID, DWORD, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpCloseHandle(HINTERNET);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpCrackUrl(LPCWSTR, DWORD, DWORD, LPURL_COMPONENTSW);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpQueryHeaders(HINTERNET, DWORD, LPCWSTR, LPVOID, LPDWORD, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI WINHTTP$WinHttpSetOption(HINTERNET, DWORD, LPVOID, DWORD);

/* ================================================================
 * CRYPT32 (certificate store for device ID discovery)
 * ================================================================ */
DECLSPEC_IMPORT HCERTSTORE WINAPI CRYPT32$CertOpenStore(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void *);
DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertFindCertificateInStore(HCERTSTORE, DWORD, DWORD, DWORD, const void *, PCCERT_CONTEXT);
DECLSPEC_IMPORT DWORD   WINAPI CRYPT32$CertGetNameStringW(PCCERT_CONTEXT, DWORD, DWORD, void *, LPWSTR, DWORD);
DECLSPEC_IMPORT BOOL    WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT);
DECLSPEC_IMPORT BOOL    WINAPI CRYPT32$CertCloseStore(HCERTSTORE, DWORD);

/* ================================================================
 * Convenience aliases to keep BOF code readable.
 * Every Win32/CRT call goes through the DFR name.
 * ================================================================ */

/* Heap */
#define bof_malloc(sz)       MSVCRT$malloc(sz)
#define bof_free(p)          MSVCRT$free(p)
#define bof_realloc(p, sz)   MSVCRT$realloc(p, sz)

/* String */
#define bof_strlen           MSVCRT$strlen
#define bof_wcslen           MSVCRT$wcslen
#define bof_strstr           MSVCRT$strstr
#define bof_strcmp            MSVCRT$strcmp
#define bof_stricmp          MSVCRT$_stricmp
#define bof_wcsicmp          MSVCRT$_wcsicmp
#define bof_strncmp          MSVCRT$strncmp
#define bof_strnicmp         MSVCRT$_strnicmp
#define bof_wcsnicmp         MSVCRT$_wcsnicmp
#define bof_strchr           MSVCRT$strchr
#define bof_wcschr           MSVCRT$wcschr
#define bof_strcpy           MSVCRT$strcpy
#define bof_wcscpy           MSVCRT$wcscpy
#define bof_strncpy          MSVCRT$strncpy
#define bof_wcsncpy          MSVCRT$wcsncpy
#define bof_strcat           MSVCRT$strcat
#define bof_wcscat           MSVCRT$wcscat
#define bof_memcpy           MSVCRT$memcpy
#define bof_memset           MSVCRT$memset
#define bof_memcmp           MSVCRT$memcmp
#define bof_snprintf         MSVCRT$_snprintf
#define bof_sprintf          MSVCRT$sprintf
#define bof_snwprintf        MSVCRT$_snwprintf
#define bof_swprintf         MSVCRT$swprintf
#define bof_atoi             MSVCRT$atoi

/* Kernel32 */
#define bof_CreateFileW      KERNEL32$CreateFileW
#define bof_ReadFile         KERNEL32$ReadFile
#define bof_WriteFile        KERNEL32$WriteFile
#define bof_FlushFileBuffers KERNEL32$FlushFileBuffers
#define bof_CloseHandle      KERNEL32$CloseHandle
#define bof_GetFileSize      KERNEL32$GetFileSize
#define bof_FindFirstFileW   KERNEL32$FindFirstFileW
#define bof_FindNextFileW    KERNEL32$FindNextFileW
#define bof_FindClose        KERNEL32$FindClose
#define bof_MultiByteToWideChar KERNEL32$MultiByteToWideChar
#define bof_WideCharToMultiByte KERNEL32$WideCharToMultiByte
#define bof_Sleep            KERNEL32$Sleep
#define bof_CreateDirectoryW KERNEL32$CreateDirectoryW
#define bof_ReadDirectoryChangesW KERNEL32$ReadDirectoryChangesW
#define bof_WaitForSingleObject KERNEL32$WaitForSingleObject
#define bof_CreateEventW     KERNEL32$CreateEventW
#define bof_GetOverlappedResult KERNEL32$GetOverlappedResult
#define bof_GetTickCount     KERNEL32$GetTickCount
#define bof_GetLastError     KERNEL32$GetLastError
#define bof_GetProcessHeap   KERNEL32$GetProcessHeap
#define bof_HeapAlloc        KERNEL32$HeapAlloc
#define bof_HeapFree         KERNEL32$HeapFree
#define bof_HeapReAlloc      KERNEL32$HeapReAlloc
#define bof_ZeroMemory       KERNEL32$RtlZeroMemory
#define bof_lstrlenW         KERNEL32$lstrlenW
#define bof_lstrcpyW         KERNEL32$lstrcpyW
#define bof_lstrcmpiW        KERNEL32$lstrcmpiW
#define bof_GetFileAttributesW KERNEL32$GetFileAttributesW
#define bof_OpenFileMappingW KERNEL32$OpenFileMappingW
#define bof_MapViewOfFile    KERNEL32$MapViewOfFile
#define bof_UnmapViewOfFile  KERNEL32$UnmapViewOfFile
#define bof_SetNamedPipeHandleState KERNEL32$SetNamedPipeHandleState
#define bof_WaitNamedPipeW   KERNEL32$WaitNamedPipeW
#define bof_CancelIo         KERNEL32$CancelIo
#define bof_GetCurrentProcessId KERNEL32$GetCurrentProcessId

/* WinHTTP */
#define bof_WinHttpOpen             WINHTTP$WinHttpOpen
#define bof_WinHttpConnect          WINHTTP$WinHttpConnect
#define bof_WinHttpOpenRequest      WINHTTP$WinHttpOpenRequest
#define bof_WinHttpAddRequestHeaders WINHTTP$WinHttpAddRequestHeaders
#define bof_WinHttpSendRequest      WINHTTP$WinHttpSendRequest
#define bof_WinHttpReceiveResponse  WINHTTP$WinHttpReceiveResponse
#define bof_WinHttpQueryDataAvailable WINHTTP$WinHttpQueryDataAvailable
#define bof_WinHttpReadData         WINHTTP$WinHttpReadData
#define bof_WinHttpCloseHandle      WINHTTP$WinHttpCloseHandle
#define bof_WinHttpCrackUrl         WINHTTP$WinHttpCrackUrl
#define bof_WinHttpQueryHeaders     WINHTTP$WinHttpQueryHeaders
#define bof_WinHttpSetOption        WINHTTP$WinHttpSetOption

/* Crypt32 */
#define bof_CertOpenStore           CRYPT32$CertOpenStore
#define bof_CertFindCertificateInStore CRYPT32$CertFindCertificateInStore
#define bof_CertGetNameStringW      CRYPT32$CertGetNameStringW
#define bof_CertFreeCertificateContext CRYPT32$CertFreeCertificateContext
#define bof_CertCloseStore          CRYPT32$CertCloseStore

#endif /* _BOFDEFS_H_ */
