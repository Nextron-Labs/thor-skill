# AV/EDR interference

Per the THOR manual, AV/EDR products cause more than 98 % of frozen scans. THOR reads process memory,
enumerates handles, probes mutexes, events and named pipes, and opens thousands of files: behaviour that
EDRs inspect, delay, suspend or kill.

## 1. Symptoms

- Process exists but CPU time stops increasing; Linux state `T`.
- CTRL+C shows the same element on every check, typically in Mutex, Events, NamedPipes/Pipes, ShimCache
  or ProcessCheck.
- Log ends without a THOR message at the same element on every run (EDR kill).
- Scan much slower than on comparable hosts. Measured by Nextron for Windows Defender: +50 to 100 % runtime
  without an exclusion (since April 2021).
- False positives in ProcessCheck from strings an EDR injects into processes (SentinelOne: e.g. `ReflectiveLoader`).

## 2. Exclusions

Exclude the THOR **process** (binary path) and, if the product needs it, the THOR program folder. Use the
real binary names: Windows `thor64.exe` (v10 also 32-bit `thor.exe`), Lite `thor64-lite.exe`; Linux
`thor-linux-64` / `thor-lite-linux-64`; macOS `thor-macosx` / `thor-lite-macosx`; AIX `thor-aix`; plus
`thor-util`/`thor-lite-util` for updates. Prefer certificate- or hash-based exclusions where the product
supports them (binaries are signed by Nextron Systems GmbH; hashes change with every upgrade).

### Microsoft Defender (local)

```powershell
# elevated PowerShell
Add-MpPreference -ExclusionProcess 'C:\thor\thor64.exe'
# or from cmd.exe
powershell -ep bypass -Command "Add-MpPreference -ExclusionProcess 'C:\thor\thor64.exe'"
# verify
(Get-MpPreference).ExclusionProcess
# remove after the scan if the exclusion was temporary
Remove-MpPreference -ExclusionProcess 'C:\thor\thor64.exe'
```
Changing Defender settings is a system security change: confirm with the user/admin first. Tamper
protection or a central policy (Intune, GPO, Defender for Endpoint) can override local settings; then add
the exclusion centrally.

### McAfee / Trellix (from the THOR manual)

- On-Access Scan: add `thor.exe` and `thor64.exe` to the **Low Risk** process exclusions.
- Access Protection: add `thor.exe` and `thor64.exe` to the exclusions of the access protection rules.

### SentinelOne

Its in-memory hooks produce ProcessCheck false positives; the manual states this cannot be excluded
generically. Triage those hits as EDR artefacts, or skip process memory checks for that host:
v10 `--noprocs`, v11 `--exclude-component ProcessCheck` (loses process detection).

### Other products (CrowdStrike, Carbon Black, Sophos, Symantec, Cortex, ...)

Add a process/path exclusion for the THOR binary (and folder) in the product's policy console, scoped to the
hosts and time window of the scan. Ask the EDR team for "exclude from behavioural blocking and on-access
scanning", not just "allow-list". Check the EDR's own event for THOR to see which action it took.

Linux EDR/auditd agents: same principle (process path exclusion). `cat /proc/<pid>/status | grep -e State
-e TracerPid` shows a stopped or traced THOR.

## 3. When exclusions are not possible

In order of preference (each step trades coverage for stability):

1. **`--soft`** (v10 and v11; the main answer in v11): disables Mutex, Firewall, LoggedIn,
   NetworkSessions, NetworkShares, LsaSessions, Hosts, DoublePulsar and executable decompression; low process
   priority; v11 also 1 thread and 50 % CPU limit (v10 70 %); process size limit 500 MB. It does **not**
   disable ProcessCheck, Events, Pipes or ShimCache. v11 refuses `--soft` with `--deep`, `--lab`,
   `--no-resource-check`; v10 silently lets `--soft` win over `--intense`/`--lab`.
2. Exclude the component that stalls (seen via CTRL+C):

   | Component | v10 | v11 |
   |---|---|---|
   | Process memory / handles | `--noprocs` | `--exclude-component ProcessCheck` |
   | Mutex probing | `--nomutex` | `--exclude-component Mutex` |
   | Event objects | `--noevents` | `--exclude-component Events` |
   | Named pipes | `--nopipes` | `--exclude-component Pipes` |
   | ShimCache | `--noshimcache` | `--exclude-component SHIMCache` |

   v11 still parses the v10 `--no...` flags (deprecated) but not all of them still act (`--noshimcache`
   does nothing in v11): use `--exclude-component`. Several components: `--exclude-component ProcessCheck,Mutex`.
3. Scan offline instead: copy or mount the evidence on an analysis host (lab license for full features).

## 4. Proving it was the AV/EDR

1. Scan a small folder with and without the exclusion and compare runtimes:
   ```
   thor64.exe -a Filescan -p C:\Windows\Temp --nothordb -e C:\thor-test          (v10)
   thor64.exe -a Filescan -p C:\Windows\Temp --no-thordb --output-directory C:\thor-test   (v11)
   ```
   Filter license lines before reading the console output: `| Select-String -NotMatch 'LICENSE_OWNER|License file found|Scan Information'`.
2. `thor-util diagnostics` while THOR hangs: `goroutine.pprof` shows where THOR waits, `progress.json` the
   tasks (see [diagnostics.md](diagnostics.md)).
3. Repeated silent deaths: `thor-util diagnostics --run` reports the killing process (v10: Windows only).
4. Escalate with: AV/EDR product + version, exclusions applied, the diagnostics pack (privacy warning in
   SKILL.md), and the EDR's own event.
