# Attribute evaluation

Weighted indicators for judging one finding. A single "bad" indicator proves nothing, so weigh the overall
picture. Field names are text-log keys. For v11 JSON, use the lowercase names under `subject` (see
[log formats](log-formats.md)).

## Location (FILE, IMAGE_FILE, PATH, IMAGE_PATH)

| Question | If yes | Weight |
|---|---|---|
| Temp folder (`C:\Temp`, `AppData\Local\Temp`, `/tmp`, `/dev/shm`)? | bad | medium |
| Directly in a folder that normally holds no executables (`C:\ProgramData\1.exe`, `C:\Users\Public`, `C:\Windows\Fonts`, `C:\PerfLogs`)? | bad | medium |
| Web root or upload folder (webshell candidates)? | bad | medium |
| On a mounted or remote share (`\\tsclient\C$`)? | bad | medium |
| In `%AppData%`? | bad | low |
| Path contains local-language business terms (`Datensicherung`, `Zeiterfassung`) or custom internal software names? | good | medium |
| Backup or archive folder on a server (`G:\Backup2007\`), old OS folder (`F:\WinNT35\`)? | good | medium |
| Looks like a deliberate admin tool (`robocopy-migration.exe`, IT tools share)? | good | low |
| Hack tool in its normal package location (`/usr/bin/ncat`)? | good | medium |
| Same path and hash on 100+ systems? | good (FP) | high |
| Search engines show it as goodware? / as malware or hack tool? / no results at all? | good / bad / bad | medium / medium / low |

## Hashes (MD5, SHA1, SHA256)

| Question | If yes | Weight |
|---|---|---|
| VirusTotal: more than 10 engines detect it | bad | high |
| VirusTotal: 3-10 detections | bad | medium |
| AV names contain `Hack`, `Tool`, `Dump`, `Password`, `Webshell`, `Cobalt`? | bad | high |
| Submitted file names are hash values or end in `.vir` | bad | low |
| VT community has negative votes or comments | bad | medium |
| Unknown to VT | neutral (bad if combined with other bad signs) | - |
| In a vendor or Microsoft software catalogue, VT "probably harmless" | good | high |
| Valid signature from a trusted vendor, and the signer matches the product | good | medium |
| First submission more than 7 years ago, and all listed file names are legitimate | good | low |

## File attributes (Filescan / `file`)

| Attribute | Question | If yes | Weight |
|---|---|---|---|
| SIZE | 0 bytes (cleaned by AV, placeholder)? | good | high |
| TYPE vs extension | Executable with a document or image extension (`.txt`, `.jpg`, `.pdf`)? | bad | medium |
| FIRSTBYTES | Script starting with plain admin commands in the local language? | good | high |
| FIRSTBYTES | Batch file starting with `net user`, `vssadmin`, `wevtutil cl`? | bad | medium |
| OWNER | A web or service account (`IIS_IUSRS`, `www-data`, `tomcat`) owns an executable or script in a web root? | bad | medium |
| OWNER | A normal user account? `BUILTIN\Administrators`? | good (low) / neutral | - |
| COMPANY / DESC (PE) | Mismatch with the file name (`svchost.exe` without Microsoft)? | bad | medium |
| Signature (v11 `pe_info.signed`) | Unsigned binary posing as a system file? | bad | medium |
| CREATED / MODIFIED | Inside the known attacker timeframe? | bad | high |
| CREATED / MODIFIED | On a weekend or at night when the organisation does not work? | bad | medium |
| CREATED / MODIFIED | Many years old and unchanged? | good | low |
| Archive member (v11 PARENT_*/ORIGIN_*) | Inside a backup or software archive vs. a user download? | context | - |

## Reasons (REASON_N, SIGCLASS_N, SIGTYPE_N, RULENAME_N)

| Question | If yes | Weight |
|---|---|---|
| Only a filename IOC matched, with no content rule? | good (FP-prone) | low |
| Rule is a vulnerable-driver or vulnerability rule (`VUL_`)? | context: legitimate software, but still a risk | medium |
| Rule is generic (`SUSP_`, `GEN_`, anomaly, packer)? | needs other signs | low |
| Rule is family- or actor-specific, or a hash IOC? | bad | high |
| `SIGTYPE_N: custom` (the user's own IOCs/rules)? | bad, if the IOC is incident-specific | high |
| User renamed a file to bypass filters (`ChromePortable.exe.txt`)? | good | medium |
| Several independent reasons (content + location + timeframe)? | bad | high |
| `MATCHED_N` is a description, comment or signature string rather than code? | good | medium |

## Execution evidence (SHIMCache, AmCache, Prefetch)

| Attribute | Question | If yes | Weight |
|---|---|---|---|
| PATH / FILE | Apply the location questions above | | |
| hash fields | Empty (file no longer on disk)? | neutral, but worth finding out why | - |
| TIMESTAMP / FIRST_RUN | Inside the attacker timeframe or very recent? | bad | medium |

## Processes (ProcessCheck / `process`)

| Attribute | Question | If yes | Weight |
|---|---|---|---|
| IMAGE_FILE | Temp, Public or user-writable location for a "system" name? | bad | high |
| COMMAND | Encoded PowerShell, `-nop -w hidden`, LOLBins with URLs, `rundll32` with an odd DLL? | bad | medium |
| PARENT / PPID | Unusual parent (Office spawning a shell, `services.exe` spawning cmd)? | bad | medium |
| OWNER | SYSTEM for a user-space tool, or a user account for a system process name? | bad | medium |
| Connections | Outbound to unusual regions or raw IPs on odd ports? | bad | medium |
| Reason | Memory-only YARA hit (image file is clean)? | bad | high |
| Image | AV, EDR, backup or indexer process with signature strings in memory? | good (FP) | high |

## Services and autoruns

| Attribute | Question | If yes | Weight |
|---|---|---|---|
| IMAGE_PATH | In a user, Temp or ProgramData root? | bad | high |
| SERVICE_NAME / ENTRY | Random, GUID-like or mimicking a vendor name? | bad | medium |
| COMMAND / LAUNCH_STRING | `cmd /c`, `powershell`, `mshta`, `regsvr32 /i:http`? | bad | high |
| FAILURE_COMMAND | Present at all? | bad | medium |
| USER | LocalSystem for third-party software that does not need it? | bad | low |
| MODIFIED | Inside the attacker timeframe? | bad | high |
| Image | Present, signed, and part of installed software? | good | medium |

## Making the call

1. Look at MODULE / `subject.type` and pick the matching section.
2. Answer the applicable questions and weight them.
3. Decide **likely FP** (document it and suppress narrowly), **unclear** (ask the owner, collect more), or
   **likely TP** (collect evidence, check other hosts, escalate).
