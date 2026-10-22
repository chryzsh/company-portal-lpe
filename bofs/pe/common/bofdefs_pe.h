/*
 * BOF-PE compatibility header.
 * Maps bof_X aliases used in the original COFF BOFs to direct Win32/CRT
 * calls. In a linked PE these resolve through the import table instead of
 * the C2's DFR thunks.
 */
#ifndef _BOFDEFS_PE_H_
#define _BOFDEFS_PE_H_

#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Heap */
#define bof_malloc(sz)       malloc(sz)
#define bof_free(p)          free(p)
#define bof_realloc(p, sz)   realloc(p, sz)

/* String */
#define bof_strlen           strlen
#define bof_wcslen           wcslen
#define bof_strstr           strstr
#define bof_strcmp            strcmp
#define bof_stricmp          _stricmp
#define bof_wcsicmp          _wcsicmp
#define bof_strncmp          strncmp
#define bof_strnicmp         _strnicmp
#define bof_wcsnicmp         _wcsnicmp
#define bof_strchr           strchr
#define bof_wcschr           wcschr
#define bof_strcpy           strcpy
#define bof_wcscpy           wcscpy
#define bof_strncpy          strncpy
#define bof_wcsncpy          wcsncpy
#define bof_strcat           strcat
#define bof_wcscat           wcscat
#define bof_memcpy           memcpy
#define bof_memset           memset
#define bof_memcmp           memcmp
#define bof_snprintf         _snprintf
#define bof_sprintf          sprintf
#define bof_snwprintf        _snwprintf
#define bof_swprintf         swprintf
#define bof_atoi             atoi

/* Kernel32 */
#define bof_CreateFileW      CreateFileW
#define bof_ReadFile         ReadFile
#define bof_WriteFile        WriteFile
#define bof_FlushFileBuffers FlushFileBuffers
#define bof_CloseHandle      CloseHandle
#define bof_GetFileSize      GetFileSize
#define bof_FindFirstFileW   FindFirstFileW
#define bof_FindNextFileW    FindNextFileW
#define bof_FindClose        FindClose
#define bof_MultiByteToWideChar MultiByteToWideChar
#define bof_WideCharToMultiByte WideCharToMultiByte
#define bof_Sleep            Sleep
#define bof_CreateDirectoryW CreateDirectoryW
#define bof_ReadDirectoryChangesW ReadDirectoryChangesW
#define bof_WaitForSingleObject WaitForSingleObject
#define bof_CreateEventW     CreateEventW
#define bof_GetOverlappedResult GetOverlappedResult
#define bof_GetTickCount     GetTickCount
#define bof_GetLastError     GetLastError
#define bof_SetLastError     SetLastError
#define bof_GetProcessHeap   GetProcessHeap
#define bof_HeapAlloc        HeapAlloc
#define bof_HeapFree         HeapFree
#define bof_HeapReAlloc      HeapReAlloc
#define bof_ZeroMemory       RtlZeroMemory
#define bof_lstrlenW         lstrlenW
#define bof_lstrcpyW         lstrcpyW
#define bof_lstrcmpiW        lstrcmpiW
#define bof_GetFileAttributesW GetFileAttributesW
#define bof_OpenFileMappingW OpenFileMappingW
#define bof_MapViewOfFile    MapViewOfFile
#define bof_UnmapViewOfFile  UnmapViewOfFile
#define bof_SetNamedPipeHandleState SetNamedPipeHandleState
#define bof_WaitNamedPipeW   WaitNamedPipeW
#define bof_CancelIo         CancelIo
#define bof_GetCurrentProcessId GetCurrentProcessId
#define bof_ResetEvent       ResetEvent
#define bof_GetModuleHandleW GetModuleHandleW
#define bof_GetProcAddress   GetProcAddress
#define bof_WaitForMultipleObjects WaitForMultipleObjects

/* WinHTTP */
#define bof_WinHttpOpen             WinHttpOpen
#define bof_WinHttpConnect          WinHttpConnect
#define bof_WinHttpOpenRequest      WinHttpOpenRequest
#define bof_WinHttpAddRequestHeaders WinHttpAddRequestHeaders
#define bof_WinHttpSendRequest      WinHttpSendRequest
#define bof_WinHttpReceiveResponse  WinHttpReceiveResponse
#define bof_WinHttpQueryDataAvailable WinHttpQueryDataAvailable
#define bof_WinHttpReadData         WinHttpReadData
#define bof_WinHttpCloseHandle      WinHttpCloseHandle
#define bof_WinHttpCrackUrl         WinHttpCrackUrl
#define bof_WinHttpQueryHeaders     WinHttpQueryHeaders
#define bof_WinHttpSetOption        WinHttpSetOption

/* Crypt32 */
#define bof_CertOpenStore           CertOpenStore
#define bof_CertFindCertificateInStore CertFindCertificateInStore
#define bof_CertGetNameStringW      CertGetNameStringW
#define bof_CertFreeCertificateContext CertFreeCertificateContext
#define bof_CertCloseStore          CertCloseStore

#endif /* _BOFDEFS_PE_H_ */
