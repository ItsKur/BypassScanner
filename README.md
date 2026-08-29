# BypassScanner

A read-only forensic scanner for Minecraft screenshares, designed to be used by a moderator,
**it detects only.** It never modifies, deletes, disables or repairs anything
If a bypass is detected it's up to moderators to decide if the flags are clear signs of bypassing.

> Work in progress. Tested for syntax and logic, but not yet validated against a
> known-tampered machine
> , contact kurvyz on discord with a clip of you running the tool if you'd like to give a demonstration

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

## Disclaimer
> **This is not a screenshare tool.** Do not use it in place of Echo, Ocean, or similar.
> Its only purpose is to check whether a user is evading detection by those tools.

This project is AI assisted, if you are experienced in powershell and would like to help this project please reach out.

To contribute a new bypass detection, open an issue describing the method first.
Pull requests are welcome for small fixes. Contributed code should be readable:
descriptive names, comments on non-obvious logic

## Philosophy behind the project

I dislike running tools that I can't be certain are safe, and I know this sentiment is true for most.
While I'm not a developer by any means I enjoy designing projects that make users more comfortable,
the first step to that is making everything free and open source and readable.

## Licence

Apache 2.0 — see [LICENSE](LICENSE) for details.


