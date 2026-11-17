# Common false positives and how to suppress them

THOR is tuned against false negatives, so a first scan of any environment produces findings that are
expected noise. Classify every finding as **expected noise** (filter it), **look closer** (ask the
system owner), or **investigate** (escalate, collect evidence, widen the scope).

| Expected noise | Look closer | Investigate |
|---|---|---|
| A security tool's own IOC or signature store matches a rule | An admin script runs from a home directory | SHIMCache/AmCache shows a credential-dumping tool ran from a public folder |
| Admin and dual-use tools (network scanner, PsExec, NirSoft) in the IT tools share | A scheduled task points to a binary that no longer exists | An unexpected account sits in the local Administrators group |
| Package manager or installer caches containing hack-tool test files | A remote-access tool on a server where nobody expects one | The same rare hit on 2-3 servers of one department |

## Sources that commonly cause FPs

| Source | Typical pattern | How to verify |
|---|---|---|
| Admin / dual-use tools | `HKTL_`/`PUA` YARA rules, filename IOCs for PsExec, NirSoft, Mimikatz-like names | Is it in a managed tools path, signed, in use for years, and on many admin hosts? |
| Security products (AV, EDR, scanners) | YARA hits on unencrypted signature databases, quarantine folders, memory of AV processes (ProcessCheck) | Path under the vendor directory, process is the AV engine, vendor-signed |
| Old THOR or other scanner output | YARA hits on `*.txt`/`*.json`/`*.html` THOR logs or reports that contain rule strings | Path is a results share or user download; type is text |
| Development and packaging | PyInstaller, AutoIt and Go binaries flagged as packed or suspicious; webshell rules on CMS/framework code | Project directory, version control metadata, hash on other dev machines |
| Backups and forensic copies | System tools in backup paths (`\\backupsrv\...\system32`), old OS folders | Path pattern, file times far in the past |
| Recycle Bin | Renamed tools (`$IR4HB6A.exe`) | Original name in the `$I` file; who deleted it |
| Web and log scanning | Vulnerability scanner requests in access logs (404s for webshell names), robocopy/backup logs listing tool names | HTTP status code, source IP = known scanner |
| Process memory | Strings of security products, VMware Tools, search indexer | Process image and signer |
| Old or rare legitimate software | Signature anomalies for unusual versions (e.g. old `javaw.exe` builds) | VirusTotal history, vendor catalogue |
| THOR itself | THOR started from `C:\Temp` shows up in SHIMCache/AmCache as a tool in a suspicious location | Path matches the scan deployment |

Generic rules (`SUSP_`, `GEN_`, `Anomaly`, filename-only reasons) need context. Specific family, APT,
webshell variant and hash IOC hits rarely need it. Check the rule in Valhalla (rule info page with
metadata, past matches, AV verdicts and statistics; the GUI is rate limited) and read `FALSEPOSITIVES_N`
for Sigma rules.

## Suppression mechanisms (choose the narrowest)

### 1. `config/false_positive_filters.cfg` (both versions)

- Lives in the THOR program folder, at a fixed path.
- Each non-empty line that does not start with `#` is a Go regular expression (RE2, no lookahead).
  There is no `RULE;PATH` two-column format.
- **v10** matches against `MODULE: <mod> MESSAGE: <msg> KEY: value KEY: value ...`, which is the text
  log line without its header (values quoted and truncated like in the log). It is applied to every
  event, including messages.
- **v11** matches against the assessment rendered as `KEY: value ` pairs (MODULE, SCANID, MESSAGE,
  SCORE, subject fields, REASON_N ...). It is applied to assessments only.
- A match **drops the event entirely**: it is not logged and not counted. A too-broad regex creates a blind spot.

```
# Shipped examples: a hash, or a rule everywhere
MD5: 6c6fe1cff88157dc2a86ef3c8467d7ac
REASON_1: YARA rule Elise_Jan18_1
# Approved NirSoft tools in the IT share only (path, then rule; FILE precedes REASON in both versions)
FILE: C:\\IT\\Tools\\NirSoft\\.*REASON_1: YARA rule HKTL_NirSoft
# One host's backup copy of system files
FILE: \\\\backupsrv\\sysbackup\\
```

Escape backslashes (`\\`) and regex metacharacters. Anchor on a hash or a distinctive path whenever
possible. Test with a short scan on a folder that holds the file, and confirm that the finding is gone
while others remain.

### 2. Trusted hashes

- A hash IOC file whose name contains the word `trusted` or `falsepositive` and the word `hash`,
  `hashes` or `md5s` (words separated by non-alphanumerics), e.g. `my-trusted-hashes.txt`. Put it in
  `custom-signatures/iocs/` (v11 requires the type subfolder; v10 reads anywhere under `custom-signatures/`).
- Lines are `hash` or `hash;comment`. MD5, SHA1 and SHA256 are accepted.
- Effect: **v10** drops all Filescan reasons for that file. **v11** adds score -100, so the total is 0.
- Best for known-good binaries flagged by generic rules. The hash covers this exact build only.

### 3. Negative-score IOCs and rules

- Filename IOC with a negative score, so a tool is fine in one place and suspicious elsewhere:
  ```
  # filename IOC;score
  \\PsExec\.exe;60
  \\SysInternals\\PsExec\.exe;-60
  ```
  `C:\SysInternals\PsExec.exe` -> combine(60, -60) = 36, which is not reported. `C:\Users\Public\PsExec.exe` -> 60,
  a Warning.
- YARA rules with a negative `score` meta, or with `falsepositive` meta (which multiplies the score by -1).
  Do not combine both.
- Scores combine multiplicatively, not by addition: -30 against 70 gives 61, not 40. A negative score
  cannot pull down a 100 hit. Only <= -100 forces 0.

### 4. Exclusions (scope, not output)

- **v10:** `config/directory-excludes.cfg`. **v11:** `--exclude-path <regex>` or `config/path-excludes.cfg`
  (the old name is still read). Also `--exclude-process`, `--exclude-registry-key` and `--exclude-eventlog` (v11).
- Excluded paths are **not scanned at all**. Use exclusions for performance or stability (database files,
  huge archives, mail stores), never to hide one known-good file.

### 5. Signature load filters (last resort)

- **v10** `--init-filter <substr>` / `--init-selector`, **v11** `--signature-exclude` / `--signature-include`.
- They stop matching signatures from **loading** at all, on every scanned host. This is a global loss of
  detection, not a per-finding suppression.

In managed setups, Analysis Cockpit baselines (filters generated after the first scan, then showing only
differences) and the Cloud Lite global settings serve the same purpose centrally.

## FP decision checklist

1. Is the file signed by a trusted vendor, and does the signer match the product?
2. Is it in the expected install location for that software?
3. Does the user's or host's role justify the tool (admin jump host vs. HR laptop)?
4. Is it rare (1-5 hosts) or everywhere (100+ hosts)?
5. Do VirusTotal and the vendor catalogue agree that it is benign? Is it old and unchanged?
6. Does the matched string prove malicious content, or only describe it (documentation, signature DB)?

If most answers say benign: document the decision and add the narrowest suppression. If most say
suspicious: treat it as a true positive until disproven. Collect the file and check other hosts.
