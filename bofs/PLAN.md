# BOF Development Plan: Company Portal Exploit Chain

## Goal

Replace the .NET CompanyPortalRecon assembly with native BOFs for the
CVE-2025-43715 NSIS race privilege escalation chain. BOFs avoid loading
the .NET CLR, reduce footprint, and improve modularity.

## Prior art

- `askwam_bof.x64.o`: WAM token acquisition BOF (already exists, step 0 of chain)
- `intune_app.c`: standalone native exe with WinHTTP + JSON for app
  list/install/uninstall (in project root). Foundation for the apps BOF.
- `bof_wam_feasibility.md`: feasibility analysis. Concluded all HTTP
  operations are BOF-feasible, WCF named pipe check-in is not.

## Components

| BOF | Status | Source | Description |
|-----|--------|--------|-------------|
| `exchange/exchange.c` | [x] Done | New | MAM→enrollment token exchange via TokenRenewalService |
| `apps/apps.c` | [x] Done | Convert intune_app.c | App list, status, install, uninstall via IWService |
| `race/race.c` | [x] Done | New | NSIS race via ReadDirectoryChangesW |

## Operational chain (BOF-only)

```
askwam BOF → exchange BOF → race BOF (arm watcher) → apps BOF (install) → SYSTEM shell
```

1. **askwam**: acquire WAM token from the logged-in user's token broker
2. **exchange**: MAM → Intune enrollment token via TokenRenewalService
3. **race**: arm the watcher on C:\Windows\Temp for ns*.tmp directories
4. **apps**: trigger an NSIS-based app install via the Intune API

IME processes the install request (via IC3 push notification or its
next timer cycle). When the NSIS installer unpacks, the race BOF
plants the payload DLL before NSIS loads its own copy. The payload
runs as SYSTEM and spawns a process in the logged-in user's session.

No .NET dependency. The WCF named pipe check-in (exec_dotnet) is not
needed: the API install request reaches IME through normal channels.

### Passive variant

If an active trigger is unnecessary or the target already has NSIS-based
apps deploying, the chain reduces to just the race BOF monitoring for
any NSIS installer:

```
race BOF (arm watcher) → wait → SYSTEM shell
```

## Build

Cross-compile from Kali:
```
x86_64-w64-mingw32-gcc -c -o bof.x64.o bof.c  # x64 BOF
i686-w64-mingw32-gcc -c -o bof.x86.o bof.c     # x86 BOF
```

Top-level `make` builds all BOFs.

## Common infrastructure

- `common/beacon.h`: Cobalt Strike BOF API (compatible with Sliver, Havoc, etc.)
- `common/bofdefs.h`: DFR declarations for KERNEL32, MSVCRT, WINHTTP, CRYPT32

## Build results

All BOFs compile clean (zero warnings) with both x64 and x86 cross-compilers.

| BOF | x64 size | x86 size |
|-----|----------|----------|
| exchange | 10,140 B | 9,025 B |
| apps | 17,210 B | 14,389 B |
| race | 6,639 B | 6,029 B |

## File layout

```
bofs/
├── PLAN.md
├── Makefile
├── common/
│   ├── beacon.h
│   └── bofdefs.h
├── exchange/
│   ├── exchange.c
│   ├── exchange.x64.o
│   └── exchange.x86.o
├── apps/
│   ├── apps.c
│   ├── apps.x64.o
│   └── apps.x86.o
└── race/
    ├── race.c
    ├── race.x64.o
    └── race.x86.o
```

## Test results (2026-10-19)

Race BOF validated end-to-end via bof-test-kit over WinRM:
- BOF planted nsExec.dll into nsi4B92.tmp across 3 events (ADDED, REMOVED, ADDED)
- payload_cmd.dll loaded as SYSTEM, found bob in session 2 via WTSEnumerateSessions
- Spawned cmd.exe as the target user in session 2 via WTSQueryUserToken + CreateProcessAsUser

Race BOF v1 (REMOVED-only, 500ms poll) caught 1 event, payload was not loaded.
Race BOF v2 (ADDED+REMOVED, 10ms poll) caught 3 events, payload loaded and executed.

Buffer-based loading (bzi format) validated 2026-10-20:
- 15,886 byte DLL received via BeaconDataExtract, plugin name and timeout parsed correctly
- Watcher loop ran for full 30s timeout, exited clean (no NSIS installer active)
- Planting already proven with disk-based v2; this confirms the in-memory arg path works

## Notes

- SERVICE_PARAMS must match the .NET assembly values:
  `api-version=18.14&ssp=WindowsUCP&ssp-version=11.2.2044.0&os=Windows&os-version=10.0.26200&os-sub=None&arch=x64&mgmt-agent=MicrosoftManagementPlatformCloudMdm`
- The intune_app.c has older service params. BOFs use the current values.
- Token exchange URL: `https://{host}/OAuth/StatelessOAuthService/OAuthProxy/?api-version=1.0`
- IWService URL: `https://{host}/TrafficGateway/TrafficRoutingService/IWService/StatelessIWService`
- OData actions: `#CommonContainer.Install`, `#CommonContainer.Uninstall`
- Host discovery: regex `fef\.[a-z0-9]+\.manage\.microsoft\.com` in IME logs
- Device ID: MDM cert CN from LocalMachine\My store, issuer contains "Microsoft Intune MDM Device CA"
