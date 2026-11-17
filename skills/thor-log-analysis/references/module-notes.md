# Module notes: interpreting findings by source

`MODULE` (text) or `meta.module` (v11 JSON) names the module or feature that produced the event. In
v11, `subject.type` names the object. Use both to choose the fields to read. Field names below are
given as text-log keys. In v11 JSON they are the lowercase names under `subject`
(see [log formats](log-formats.md)). Run `--describe-object-type <type>` on THOR 11 to list all fields of a type.

Module names seen in both versions include Filescan, ProcessCheck, Eventlog, RegistryChecks, ServiceCheck,
Autoruns, ScheduledTasks, WMIStartup, AtJobs, Mutex, Pipes, DNSCache, NetworkSessions, NetworkShares,
Firewall, Hosts, Users, UserDir, LoggedIn, LSASessions, MFT, Rootkit, Timestomp, Integritycheck (Linux),
Cron, Antivirus, HotfixCheck and EndOfLife. v11 adds ebpf, lsmod and others. Events from files found
during the file scan (EVTX, registry hives, log files, SHIM/AmCache inside hives) may carry the feature
name instead of `Filescan`.

## Filescan (files on disk, including archive members)

| | v10 text keys | v11 (`file`) |
|---|---|---|
| Location | FILE, EXT, ARCHIVE_* for members | FILE (`path`), EXTENSION, PARENT_*/ORIGIN_* (`ancestors`) for archive members, e.g. `/srv/www/site-backup.zip/shell-copy.php` |
| Content | TYPE (magic), SIZE, FIRSTBYTES `hex / ascii`, MD5/SHA1/SHA256 | TYPE (`magic_header`), SIZE, FIRSTBYTES, `hashes`, EXISTS |
| Time / owner | CREATED, MODIFIED, ACCESSED, CHANGED, OWNER, PERMISSIONS | same, under `file_times`, `permissions` |
| PE info | COMPANY, DESC, PRODUCT, ORIGINAL_NAME, INTERNAL_NAME, LEGAL_COPYRIGHT, IMPHASH | `pe_info{company, description, ..., signed, signatures, imphash}` |

- The most common source of findings. Check TYPE against the extension (an EXE named `.txt` or `.jpg`),
  PE COMPANY against the name (`svchost.exe` without Microsoft), and the location.
- Files above the size limit are not content-scanned or hashed (v10 30 MB, v11 64 MB by default). Filename
  IOCs still apply. A filename-only reason on a large file is weak evidence.
- Hash IOCs and generic YARA rules only apply to files selected for deep scanning (by type/extension or
  meta rules). Not detected does not mean not present. See the `thor-custom-signatures` skill.
- Follow up: hash lookup, Valhalla rule info, collect the file (keep timestamps), sandbox, check other
  hosts for the same hash.

## ProcessCheck (running processes)

| v10 keys | v11 (`process`) |
|---|---|
| PID, PPID, PARENT, PROCESS_NAME, COMMAND, OWNER, CREATED, SESSION, IMAGE_FILE, IMAGE_MD5/SHA1/SHA256, CONNECTION_COUNT, LISTEN_PORTS | PID, NAME, COMMAND, OWNER, IMAGE_* (`image`), PPID, PARENT, PARENT_COMMAND (`parent_info`), TREE, CREATED, SESSION, LISTEN_PORTS, CONNECTION_COUNT |

- Detection types: YARA on process memory, image-file rules or IOCs, location anomalies (started from
  Temp/Public), parent/child anomalies, masquerading system process names, suspicious connections, and
  named handles (mutex/event IOCs).
- A memory-only hit (the image file is clean) on an unexpected process is a strong signal. Hits inside AV/EDR,
  backup or search-indexer processes are often signature strings held in memory.
- **v10** logs every process at Info as "Process info". **v11** logs every process as an Info assessment
  by default. Neither is a finding.
- Follow up: process tree, command line, network connections, memory dump (THOR process dumps,
  `--dump-procs`), image file collection.

## Eventlog (live Windows event logs) and EVTX files

| v10 keys | v11 (`eventlog entry`) |
|---|---|
| EVENT_ID, EVENT_LEVEL, EVENT_CHANNEL, EVENT_COMPUTER, EVENT_TIME, ENTRY, SCORE, REASON_N (Sigma title) | EVENT_ID, EVENT_LEVEL, EVENT_TIME, EVENT_CHANNEL, EVENT_COMPUTER, ENTRY (`entry{...}` key/value) |

- Mostly Sigma rules. Subscore is by level: low 40, medium 50, high 70, critical 100. Only rules >= the
  Sigma threshold are loaded (default `high`). Read `FALSEPOSITIVES_N` and `TAGS_N` (ATT&CK).
- Muting: after 10 matches per rule, further matches are suppressed, and a Notice says so. Counts are
  incomplete beyond that point.
- Some 10.7 builds lost the EventID of records whose EventID carries a `Qualifiers` attribute (e.g. 7045
  service installs), so EventID-based Sigma rules could miss them. If 7045 hits are expected but absent
  on v10, check the changelog of the build used.
- High-value event IDs: 4624/4625 logon, 4688 process creation, 4697/7045 service install, 1102/104
  log cleared, 4720/4732 account or group changes, Sysmon 1/3/11.
- Follow up: build a timeline around the event (`thor-lens`), pivot on the user, logon ID and host.

## Log files (LogScan) and log lines

- Text log files (web server, application, auth logs) are checked line by line with log/keyword
  YARA rules, filename and keyword IOCs, and (v11) Sigma and C2/domain IOCs. **v11** selects log files
  through meta rules (`LOGSCAN` tag).
- The v11 object is `log line` (`line`, `line_index`). The log file is the parent in `ancestors` (text
  `PARENT_FILE`).
- Typical FPs: vulnerability scanner requests (404s for webshell names), backup or robocopy logs that list
  tool names, and THOR's own old logs. Check the HTTP status code and the source IP.

## Registry (RegistryChecks live, registry hive files)

| v10 keys | v11 |
|---|---|
| KEY, ENTRY, VALUE, MODIFIED, REASON_N, MATCHED_N | `registry key` (KEY, MODIFIED, VALUES) / `registry value` (KEY, MODIFIED, VALUE, SIZE) |

- Hits come from registry YARA rules (`KEYPATH;VALUENAME;VALUE` format), filename IOCs on values, and keyword IOCs.
- Persistence locations: Run/RunOnce, Winlogon, Image File Execution Options (debugger), services, COM hijacks.
- FPs: values that reference backup copies of system files, keyboard layout preload entries for the
  local region, and binary values that start with `4d5a` by coincidence.

## SHIMCache and AmCache (execution evidence)

| | v10 keys | v11 |
|---|---|---|
| SHIMCache | TIMESTAMP, EXEC_FLAG, PATH, HIVE, FILE_* (if the file still exists) | `shim cache entry` (TIMESTAMP, EXEC_FLAG, PATH) |
| AmCache | FILE, SHA1, SIZE, DESC, FIRST_RUN, CREATED, PRODUCT, COMPANY | `AmCache entry` (FILE_*, SHA1, SIZE, DESC, FIRST_RUN, CREATED, PRODUCT, COMPANY) |

- These entries prove that a path was present or executed even if the file is gone. AmCache SHA1 is
  recorded by Windows and still useful after deletion.
- The meaning of the SHIMCache timestamp depends on the Windows version (often the file's last
  modification time, not the execution time).
- A tool path in a public or temp folder is a "look closer" item: confirm with the owner, then escalate.
- **v10** "Found entry in suspicious directory" Warnings carry no SCORE. **v11** does not log SHIM cache
  entries by default (only findings).

## Persistence: Autoruns, ServiceCheck, ScheduledTasks, WMIStartup, AtJobs, Cron

| | v10 keys | v11 |
|---|---|---|
| Autoruns | TYPE, LOCATION, IMAGE_PATH, IMAGE_NAME, ARGUMENTS, MD5, SHA256, ENTRY, LAUNCH_STRING | `autorun entry`: AUTORUN_TYPE, LOCATION, image FILE_*, ARGUMENTS, ENTRY, LAUNCH_STRING, MD5_BEFORE |
| ServiceCheck | KEY, KEY_NAME, SERVICE_NAME, IMAGE_PATH, MODIFIED, START_TYPE, USER, DESCRIPTION, FAILURE_COMMAND, IMAGE_MD5/SHA1/SHA256 | `Windows service` (KEY, KEY_NAME, SERVICE_NAME, MODIFIED, START_TYPE, SERVICE_TYPE, USER, DESCRIPTION, COMMAND, IMAGE_*), plus `systemd service` and `init.d service` |
| Scheduled tasks | task name, path, command | `scheduled task` (NAME, PATH, commands, triggers, USER, RUN_LEVEL, LASTRUN) |

- **v10** Autoruns reports "New or changed autoruns element" (score 50) when ThorDB has an older state.
  It is only meaningful on repeated scans, and expected after software updates.
- Bad signs: an image in a user, Temp or ProgramData root; a random or GUID-like service name; a
  service command with `cmd /c`, `powershell -enc` or `rundll32` with an odd DLL; a failure command; a
  task pointing to a deleted binary.
- Follow up: when was it created (`MODIFIED`, task registration time)? Who created it? Is the image
  present and signed?

## Other modules (short)

| Module / object | What to look at |
|---|---|
| Mutex / `mutex`, `event`; Pipes / `named pipe` | IOC or rule name. Map it to the owning process (ProcessCheck handles) |
| DNSCache / `DNS cache entry`, Hosts / `hosts file entry` | Domain IOC hits; hosts-file redirects of security or update domains |
| NetworkSessions, NetworkShares, Firewall / `firewall rule` | Unexpected shares (`C$` exposure), sessions from unusual hosts, allow rules for odd binaries |
| Users, UserDir, LoggedIn, LSASessions | New local admins, unexpected accounts, profiles created in the incident window |
| MFT / `MFT entry`, Timestomp | Deleted or renamed files, timestamp anomalies. Correlate with Filescan paths |
| Rootkit, Integritycheck (Linux package verification), lsmod / `Linux kernel module`, ebpf | High value but rare. Verify against the package manager or vendor before concluding |
| Antivirus (`antivirus product`, `antivirus exclusion`) | Exclusions for Temp, user folders or whole drives are a common attacker change |
| DeepDive / `file chunk` (memory or image chunks) | Hits in raw data without a file context. Use the offset to carve |

## Which modules ran

A scan restricted with `-a/--module` (both versions), the v10 `--no<module>` flags, or v11
`--exclude-component` has no findings from the other modules. Scan mode also matters. Check the
startup lines (v11: the `Scan Information` record lists active modules, but it also contains license
data, so read only `active_modules`) before concluding "nothing found":

```bash
jq -r 'select(.message=="Scan Information") | .fields | .. | .active_modules? // empty | .[]' f.jsonl
```
