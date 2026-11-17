# Diagnostics: debug output, timing, thor-util diagnostics, pprof, support

## 1. Debug and trace output

| Purpose | v10 | v11 | Notes |
|---|---|---|---|
| Debug lines (skips, timeouts, deep-scan decisions) | `--debug` | `--debug` | Also disables the log size limit. Logs grow to 30-200 MB |
| Execution trace | `--trace` | `--trace` | Very verbose (RAM every 2 s, ThorDB ops); keep runs short |
| Every checked file | `--printall` | `--print-files` (alias `--printall`) | |
| Object logging | - | `--log-object <type>` (e.g. `file`) | Logs described objects of that type |
| Text log copy | default `.txt` | `--text FILE` (JSONL stays default) | Support prefers a text or JSONL debug log |
| Disable TUI to see raw lines | - | `--no-tui` | Note: CTRL+C then exits immediately |

Narrow before you debug: `-a Filescan -p <dir>` (v10/v11) or a single module (`-a Eventlog --lookback 1`).
Example (v11): `thor64.exe -a Filescan -p C:\suspect --debug --print-files --text C:\thor-out\debug.txt --no-thordb --output-directory C:\thor-out`
Filter license lines before reading console output or the debug log:
`grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'`
(PowerShell: `Select-String -NotMatch 'LICENSE_OWNER|License file found|Scan Information'`).

## 2. Hidden diagnostic flags (verified in both versions unless noted)

| Flag | Effect |
|---|---|
| v10 `--bulkstats`, v11 `--statistics` (aliases `--bulkstats`, `--bulk-stats`) | At scan end, Info lines `Reason for Bulk being scanned in detail`, `Reason for deep scan being activated`, v10 `Reason for feature scan being activated`, v11 `Hook statistics` with duration and count. Only the top N per category, N = v10 `--max-reasons` / v11 `--alert-reason-limit` (default 2; 0 = all; deep/lab already 0) |
| `--show-timeout` | YARA timeouts logged as Error instead of Debug |
| `--print-rescontrol` | RAM line every 2 s (total, free, average, remaining, threshold) |
| `--progress-output FILE` | JSON status every second (module, progress, worker tasks, recent CPU-wait %) |
| `--cpuprofile`, `--memprofile`, `--mutexprofile`, `--clockprofile`, v11 `--traceprofile` | Go profile written to the current directory; only one at a time |
| `--pprof` | HTTP pprof server on port 8080 bound to **all interfaces**. Only on isolated systems and only if support asks |
| v11 `--profile-yara` | YARA profiling (hidden); use only on support request |

YARA runs through cgo: Go CPU profiles show time inside YARA as one block and cannot name slow rules. For
"which rule/selector costs time" use `--bulkstats`/`--statistics` or the ThorDB `times` table (`thor-db` skill).

Bulk warning shown without any flag: Warning `Rule or IOC often caused Bulk being scanned in detail without
causing a match` names an expensive, unproductive custom rule or IOC.

## 3. Timing data without rerunning

- ThorDB `stats`: per module (`Whole Module`), per scan root, per directory down to depth 2 or any directory
  that took >= 20 s, per event log (Windows). Durations in seconds. Last run only.
- ThorDB `times`: deep-scan selectors, bulk rules, v11 hooks (v10 feature scans). Nanoseconds. Written only
  at a clean exit (not after a crash/kill). Last run only.
- `Maximum runtime has been exceeded` message: current elements and durations.

ThorDB does not exist for `--lab`, Dropzone and v11 `--http-server` scans. Use the `thor-db` skill for paths,
schema and read-only queries.

## 4. `thor-util diagnostics`

Lite edition: `thor-lite-util diagnostics`. Run as the same user as THOR (admin/root), from a second shell,
**while THOR still runs**. THOR exposes a local endpoint (`/tmp/thor-status` socket on Unix,
`\\.\pipe\thor-status` on Windows); only one THOR instance can serve it.

```sh
thor-util diagnostics --output /tmp/diag.zip      # default: diagnostics.zip in the current directory
thor-util diagnostics --run                        # rerun last scan with --debug --trace, then pack
thor-util diagnostics profile -o heap.pprof heap  # v11, hidden: one profile from the running THOR ('-' = stdout)
```

Pack contents:

| File | When | Content |
|---|---|---|
| `thor.dmp` | THOR running; real dump on **Windows only** (empty entry elsewhere) | Process memory dump of THOR |
| `parameters.json` | THOR running | Parsed scan configuration |
| `progress.json` | THOR running | Modules, worker tasks, CPU-wait percentage |
| `memstats.json` | THOR running, v11 | Go memory statistics |
| `cpu.pprof` (20 s sample), `heap.pprof`, `goroutine.pprof` | THOR running | Go profiles |
| `newestlog.txt` (v10, newest `*.txt`) / `newestlog.json` (v11, newest `*.jsonl`) | always | Newest log **from the THOR program folder only** |
| `thordb.db` | if present | ThorDB from the **default** path only (ignores `--dbfile`/`--thordb-path`) |
| `heap.pprof` from the THOR folder | after a resource-control abort | Heap profile THOR wrote on abort |
| `processlist.json` | always | Name, image, PID, PPID of all processes |
| `diagnostics.log` | always | Log of the collection |

`No running THOR process found` -> only log, DB and process list are packed.

`--run` caveats: it reruns the **whole** last scan (hours), reads the arguments from the newest log in the THOR
program folder (v10 "Effective argument list", v11 scan information event), so it fails when logs were written
elsewhere (`-e`, `--output-directory`). It adds `--debug --trace`, waits for THOR to finish and reports
`THOR was killed by process <image> (<pid>)` if another process terminated it (v10: Windows only). With
`--run` no dump/profiles/progress are collected.

## 5. Reading pprof files

Needs Go (`go tool pprof`); Graphviz only for graph images.

```sh
unzip diag.zip -d diag && cd diag
go tool pprof -top cpu.pprof                  # where CPU time goes (20 s sample)
go tool pprof -top -cum cpu.pprof
go tool pprof -top heap.pprof                 # what holds memory
go tool pprof -http=localhost:8080 cpu.pprof  # flame graph and call graph in the browser
go tool pprof -png heap.pprof > heap.png      # needs Graphviz
go tool pprof -traces goroutine.pprof | less  # full stacks of all goroutines
```

Interpretation:
- `goroutine.pprof`: many workers in file reads/`syscall` -> I/O or AV/EDR holding files; workers in
  `runtime.cgocall` -> inside YARA; workers waiting on a CPU-limit or interruption condition -> throttled or paused.
- `heap.pprof`: large buffers from archive/e-mail/OLE parsing -> lower the file size limit or threads (v10
  allocates a buffer of the full limit per open archive/e-mail/Office file per thread).
- `progress.json`: the current task per worker and how long it runs; `RecentCpuWaitPercentage` high -> CPU limit.

## 6. What support needs

1. `thor64.exe --version` / `./thor-linux-64 --version` / `./thor-macosx --version` (THOR, YARA, signature versions).
2. Platform: Windows `systeminfo > systeminfo.txt`; Linux `uname -a`; macOS `system_profiler -detailLevel mini > sys.txt`.
3. Exact command line (mask `--portal-api-key`/`--portal-key`, `--management-center-token`, passwords).
4. Hang: diagnostics pack taken while running. Crash: console output (`fatal error: ...`) or screenshot.
5. Optional: narrowed `--debug` log (compressed; usually < 10 MB zipped).
6. Optional for "too slow"/"max runtime": the ThorDB file (v10 `thor10.db`, v11 `thor.db`).
7. Optional: the offending file (event log, hive) if shareable; ask support for an upload link for large files.

Privacy and safety before sharing: packs and logs contain host names, user names, paths, findings, the full
process list, a THOR process memory dump (Windows, includes loaded signatures and scanned data) and license
lines with the licensee name. Tell the user to review, redact host names/IPs if required, and send through
the support channel only. Never paste `LICENSE_OWNER`, `License file found` or v11 `Scan Information` lines into chats or tickets.
