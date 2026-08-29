# BypassScanner

A read-only forensic scanner for Minecraft screenshares, sesigned to be used by a moderator,
**it detects only.** It never modifies, deletes, disables or repairs anything
If a bypass is detected it's up to moderators to decide if the flags are clear signs of bypassing.

> Work in progress. Tested for syntax and logic, but not yet validated against a
> known-tampered machine
> , contact kurvyz on discord with a clip of you running the tool if you'd like to give a demonstration

## Read this before running it

This tool was made fully open source so players can have peace of mind running it

- **One file.** `BypassDetector.ps1`, no modules, no DLLs, no downloads
- **Read-only.** No `Set-*`, `Remove-*`, `New-ItemProperty` or `Stop-Service`
  against anything on the system. The only write is the optional report file
- **No network calls.** Nothing is uploaded. No telemetry, no update check.
- **No obfuscation.** No `Invoke-Expression`, no `-EncodedCommand`, no base64

Every check has a comment header saying which files or registry keys it reads

## Usage

Requires Windows PowerShell 5.1 or later, run as Administrator, the script **will not run** if it isn't run as administrator

```powershell
powershell -ExecutionPolicy Bypass -Command "& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/ItsKur/BypassScanner/main/BypassDetector.ps1'))) -IncludeSysMainCheck"
```

> Runs [`BypassDetector.ps1`](https://github.com/ItsKur/BypassScanner/blob/main/BypassDetector.ps1) directly from this repo

| Parameter | Type | Effect |
|---|---|---|
| `-IncludeSysMainCheck` | switch | Enables check 12 and its `Add-Type` block. Off by default. |
| `-OutputPath` | string | Writes a plain UTF-8 copy of the report. No file is written without it. |
| `-Quiet` | switch | Suppresses the per-check clean lines. |

Exit codes: `0` clean, `1` one or more detections, `2` the run could not complete

Results are grouped into **Detected**, **Unavailable** and **Clean**. A check
that could not run will report as Unavailable.

## Detections

| # | Check | # | Check |
|---|---|---|---|
| 1 | Internet Options — Restricted Zones | 12 | SysMain — sechost.dll suspended threads |
| 2 | Firewall.cpl restrictions | 13 | Browser URL blocklist |
| 3 | Hosts file manipulation | 14 | CMD colour bypass |
| 4 | Taskkill autorun | 15 | Disallowed certificates |
| 5 | DisallowRun | 16 | Group policy restrictions |
| 6 | IFEO — Image File Execution Options | 17 | System time changes |
| 7 | WinRAR steganography | 18 | Event log cleared |
| 8 | NTFS journal deletion | 19 | Smart App Control / app install source |
| 9 | FileInfo filter | 20 | USB / disk devices disabled |
| 10 | Prefetch — read-only `.pf` files | 21 | SettingsPageVisibility |
| 11 | Prefetch parameters | 22 | NotFileMru |

Check 12 is opt-in because it is the only one that compiles inline C#. It reads
thread suspend counts via `NtQueryInformationThread` without altering them.

## Licence

Apache 2.0 — see [LICENSE](LICENSE) for details.
