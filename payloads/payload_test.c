/*
 * payload_test.c - Diagnostic payload for the NSIS race
 *
 * Writes a marker synchronously when NSIS loads the DLL and again if NSIS
 * calls one of the nsExec plug-in exports. Keeping the work synchronous avoids
 * a worker thread being unmapped when NSIS rejects or unloads the DLL.
 *
 * Compile (x86):
 *   i686-w64-mingw32-gcc -shared -o payload_test.dll payload_test.c -lkernel32
 *   i686-w64-mingw32-strip payload_test.dll
 */

#include <windows.h>

typedef struct _stack_t stack_t;

static void write_marker(const char *message)
{
    HANDLE file;
    SYSTEMTIME now;
    char line[256];
    DWORD length;
    DWORD written = 0;

    file = CreateFileA(
        "C:\\Windows\\Temp\\race_won.txt",
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (file == INVALID_HANDLE_VALUE)
        return;

    GetLocalTime(&now);
    length = (DWORD)wsprintfA(
        line,
        "[%04u-%02u-%02u %02u:%02u:%02u] PID=%lu %s\r\n",
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        (unsigned long)GetCurrentProcessId(),
        message);
    WriteFile(file, line, length, &written, NULL);
    CloseHandle(file);
}

__declspec(dllexport) void Exec(
    HWND hwnd_parent, int string_size, void *variables, stack_t **stack_top)
{
    (void)hwnd_parent;
    (void)string_size;
    (void)variables;
    (void)stack_top;
    write_marker("nsExec::Exec invoked");
}

__declspec(dllexport) void ExecToLog(
    HWND hwnd_parent, int string_size, void *variables, stack_t **stack_top)
{
    (void)hwnd_parent;
    (void)string_size;
    (void)variables;
    (void)stack_top;
    write_marker("nsExec::ExecToLog invoked");
}

__declspec(dllexport) void ExecToStack(
    HWND hwnd_parent, int string_size, void *variables, stack_t **stack_top)
{
    (void)hwnd_parent;
    (void)string_size;
    (void)variables;
    (void)stack_top;
    write_marker("nsExec::ExecToStack invoked");
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        write_marker("payload_test loaded");
    }
    return TRUE;
}
