# Example: Windows domain sweep from a read-only share via GPO

Goal: scan ~800 Windows clients and servers in three waves, results on one share, alerts also
to the SIEM. THOR 11 shown; THOR 10.7 differences are marked.

## 1. Shares and permissions (file server `fs01`)

| Share | Content | Share + NTFS rights |
|---|---|---|
| `\\fs01\thor$` | unpacked THOR folder | `Domain Computers`: Read; admins: Full |
| `\\fs01\thor-results$` | results | `Domain Computers`: Modify (create/write files); admins: Full; nobody else |

`$` hides the shares from browsing. Scheduled tasks run as SYSTEM and authenticate as the
computer account `DOMAIN\HOST$`, hence `Domain Computers`.

## 2. Prepare the folder (admin workstation with internet access)

```bat
C:\thor> thor-util.exe update
C:\thor> thor-util.exe yara-forge download --ruleset core
C:\thor> rem copy custom IOCs/YARA/Sigma to custom-signatures\iocs, \yara, \sigma (v11 layout)
C:\thor> rem licenses: one .lic per host (or one Incident Response license) into C:\thor\licenses\
C:\thor> robocopy C:\thor \\fs01\thor$ /MIR
```

`config\thor.yml` on the share (v11):

```yaml
output-directory: '\\fs01\thor-results$'
timestamp-utc: true
remote-log: ['siem01.corp.internal:514:JSON:TCP']
cpu-limit: 60
stats-csv: '<hostname>_stats.csv'
```

THOR 10.7 equivalent:

```yaml
rebase-dir: '\\fs01\thor-results$'
utc: true
jsonfile: ':hostname:_thor_:time:.json'
jsonv2: true
syslog: ['siem01.corp.internal:514:JSON:TCP']
cpulimit: 60
stats-file: ':hostname:_stats.csv'
```

Single quotes keep backslashes literal. Default file names contain the host name, so all hosts
share one flat results folder.

## 3. Test

On a test client (elevated prompt):

```bat
\\fs01\thor$\thor64.exe -a Filescan -p C:\Windows\Temp --no-thordb
```

Then as SYSTEM, the way the task will run it, with the same restrictions:
`psexec -s \\fs01\thor$\thor64.exe -a Filescan -p C:\Windows\Temp --no-thordb`.
Check: license accepted (no license error at startup), results and `*_stats.csv` appear in
`\\fs01\thor-results$`, SIEM receives events.

Pilot (not a test; only with the user's approval): run the unrestricted scheduled scan on 2-3
hosts, including one server of each important role, and check scan duration and CPU load.

## 4. GPO

Group Policy Management → new GPO `THOR Sweep W1`, linked to the OU (or security-group
filtered) for wave 1.

Computer Configuration → Preferences → Control Panel Settings → Scheduled Tasks →
New → **Immediate Task (At least Windows 7)**:

- General: name `THOR Scan`; user `NT AUTHORITY\System`; *Run whether user is logged on or
  not*; *Run with highest privileges*.
- Actions: Start a program → `\\fs01\thor$\thor64.exe` (no arguments; `thor.yml` has them).
- Settings: *Stop the task if it runs longer than* 3 days (must exceed the longest scan).
- Common: **Apply once and do not reapply**.

Hosts start within the next policy refresh (90 min ± 30 min). Force on a host:
`gpupdate /force`. For a fixed start time use *Scheduled Task (At least Windows 7)* with a
one-time trigger instead.

## 5. Waves

| Wave | Scope | Start |
|---|---|---|
| 1 | internet-facing servers, admin workstations | day 1, 09:00 |
| 2 | remaining servers (busy ones: separate GPO with `--soft` in a `-t` template) | day 1, after wave 1 has settled (~1 h+) |
| 3 | clients by OU/site, VDI pools in small groups | day 2 |

Per-group options without changing the shared `thor.yml`: put them in an extra template
(`\\fs01\thor$\config\servers-soft.yml` with `soft: true`) and use the task argument
`-t \\fs01\thor$\config\servers-soft.yml`.

## 6. Monitor and collect

```powershell
# finished hosts and counts (v11 stats CSV)
Get-Content \\fs01\thor-results$\*_stats.csv | Set-Content C:\sweep\all-stats.csv
# alerts across all hosts (v11 JSON)
Get-ChildItem \\fs01\thor-results$\*.jsonl | ForEach-Object {
  Get-Content $_.FullName | ConvertFrom-Json |
    Where-Object { $_.type -eq 'THOR assessment' -and $_.meta.level -eq 'Alert' } |
    Select-Object @{n='host';e={$_.meta.hostname}}, score, message }
```

v10: `findstr /C:"Alert:" \\fs01\thor-results$\*.txt`.

Missing hosts: offline, GPO not applied (`gpresult /r`), share access denied for the computer
account, no license for that host name, or a scan still running (scan lock).

## 7. Clean up

Unlink or delete the GPO (Immediate Tasks with "apply once" don't re-run, but remove the GPO
anyway), revoke `Domain Computers` access to both shares, move results to evidence storage.
