# Why a scan stopped early

Rule of thumb: an Error line from THOR at the end of the log = THOR's own decision (or a signal it caught).
A log that just stops = something killed THOR (SIGKILL, AV/EDR, OOM killer, power loss, crash before the
log was flushed).

Read the end of the log with the license filter from SKILL.md. v11: also look at the console/TUI output and
any `fatal error:` text printed by the Go runtime on stderr (not in the log).

## 1. Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed. Alerts and warnings do **not** change the exit code. v10 also exits 0 when a `-p` path did not exist |
| 1 | Every abort or error: invalid license, bad or unknown flag, "already running", insufficient RAM at start, resource control, timeout, interrupt, SIGTERM/SIGHUP/shutdown, crash/panic |

On exit code != 0 THOR skips the "Results"/"Thor Scan finished" lines **and the HTML report**. Build it
afterwards with `thor-util report --logfile <log>` (see the `thor-maintenance` skill).

## 2. Abort reasons with exact messages

### Resource control (RAM)

Every 2 s THOR compares free RAM (rolling average over the last 20 samples, ~40 s) with the limit.

| | v10 | v11 |
|---|---|---|
| Flag (default) | `--minmem 50` (plain number = **MB**) | `--memory-limit 50MB` (plain number = **bytes**; aliases `--minmem`) |
| Message | `Available physical memory dropped below 50 MB, stopping THOR scan in order to avoid a memory outage (use --minmem 0 to disable this protection)` | same text with `(use --memory-limit 0 to disable this protection)` |
| Follow-up | 3x Notice `Process with high memory usage` (MEMORY_USAGE in %), `Wrote THOR memory profile` -> `heap.pprof` next to the THOR binary | same, MEMORY_USAGE as absolute RSS |
| Disable | `--minmem 0`, or `--norescontrol` (also drops the log size limit; CPU limit stays) | `--memory-limit 0`, or `--no-resource-check` (also CPU limit to 100 % unless `--cpu-limit` is set, drops the default log size limit; incompatible with `--soft`) |
| Already off in | `--lab`, `--dropzone`, `--thunderstorm` (NOT `--intense`) | `--lab`, `--dropzone`, `--http-server`, **`--deep`/`--intense`** |

Migration trap: a v10 `config/thor.yml` with `minmem: 50` kept by an in-place upgrade means 50 **bytes** in
v11, i.e. the guard is effectively off. THOR 11 warns about such tiny values.

Fix order: find the competing process from the 3 Notice lines -> reduce THOR memory (fewer `--threads`,
default file size limit, `--soft`) -> only then lower or disable the guard. The guard is a floor of free
RAM, not a cap on THOR.

Disk: when the THOR program folder has less than 1 MiB free, THOR logs Warning `Low available disk space`
once and **continues**. There is no disk-full abort.

### Startup gate

`System has < 50 MB free RAM, can't initialize THOR` (exit 1, both versions, independent of the flags above).

### Timeout

| | v10 | v11 |
|---|---|---|
| Flag | `--max_runtime <hours>` | `--timeout <hours>` (aliases `--max_runtime`, `--max-runtime`) |
| Default | 168 h, **also in `--lab`**; 0 = none; only `--thunderstorm` sets 0 | 168 h, also in `--lab`; only `--http-server` sets 0 |
| Message | Error `RuntimeWatcher: Maximum runtime has exceeded, killing THOR` | `Maximum runtime has been exceeded, killing THOR` |

The message lists the active module and the current elements with their durations: that is your bottleneck.
A management tool (Management Center job, GPO task "stop the task if it runs longer than") can impose its
own, shorter limit.

YARA per-scan timeout (`--yara-timeout`, default 90 s) never stops the scan: the element is skipped and the
timeout logged at Debug level (Error with the hidden `--show-timeout`).

### Log size limit (false positive flood)

| | v10 | v11 |
|---|---|---|
| Reduced logging | > 60,000,000 bytes: only Notice and above; message reads `Logged more than 0 MB, switching to reduced logging` (cosmetic bug) | 4 MB before the limit: `Logged more than N MB, switching to reduced logging` |
| Exit | > 64,000,000 bytes: `Logged more than 64 MB, exiting THOR to prevent log flooding due to a high number of false positives` | `--log-size-limit` (default 200MB, 0 = off), same message with the limit |
| Not applied with | `--norescontrol`, `--printall`, `--debug`, `--trace`, `--printshim`, `--printamcache`, or no log output | `--no-resource-check`, `--print-files`, `--debug`, `--trace` (default limit only) |

Fix the cause (a noisy custom rule, a false positive filter in `config/false_positive_filters.cfg`), not the limit.

### User interrupt and signals

| Message | Cause |
|---|---|
| `Received interrupt signal.` then `THOR was terminated by interrupt command.` | v10: CTRL+C, then `E` |
| `Non-interactive mode, exiting.` | v10: CTRL+C/SIGINT without TTY or console output |
| `THOR was terminated by user request.` | v11: `E`/`Q` or a second CTRL+C in the TUI menu |
| `Received interrupt signal, exiting.` | v11: SIGINT without TUI, or sent with `kill -INT` |
| `Received shutdown signal, exiting.` (SIGNAL: ...) | SIGTERM/SIGHUP, console window closed, Windows logoff/shutdown (both versions) |
| `System was suspended during the THOR scan` (Info) | v11 Windows: sleep/hibernate during the scan |

### Crash

`THOR has paniced, stopping execution`, `THOR has paniced during shutdown`, `Module has paniced`: a bug.
Send the log, console screenshot and `--version` output to support.

Go runtime `fatal error: out of memory` (stderr, not in the THOR log): THOR could not allocate memory.
Causes: other processes, a very memory-hungry element, restrictive ulimits (`ulimit -a`: locked memory,
address space, open files, data size), `--deep`/MFT analysis. Try `--soft` and the default size limit.
On Linux THOR warns at start: `resource limit for <X> is low for THOR, consider raising it`.

### Other startup exits (exit 1)

`No valid license file found`, `The current license type doesn't allow ...`, `THOR already running`,
unknown flag / "Positional arguments specified" (e.g. `-p A B`; repeat `-p` per path), `--soft and
--no-resource-check are incompatible` (v11; also `--soft` with `--deep`/`--lab`). See
[common-pitfalls.md](common-pitfalls.md).

## 3. No message at all: external termination

Likelihood (manual): AV/EDR > user/admin > management tool killing high-CPU processes > attacker.

| Check | How |
|---|---|
| Same element every time? | CTRL+C output / last Info lines of several runs. Same element -> AV/EDR reacting to it |
| Linux OOM killer | `dmesg -T | grep -i -e 'killed process' -e oom` or `journalctl -k | grep -i oom` |
| Windows | Event Log (Application/System), AV/EDR console detections for `thor64.exe` |
| Who killed it | `thor-util diagnostics --run` reruns the last scan with `--debug --trace` and reports `THOR was killed by process <image> (<pid>)` (v10: Windows only) |
| User | Fans/lag complaints on notebooks: lower v10 `--cpulimit` / v11 `--cpu-limit`, `--soft`, run off-hours |

`--run` costs a full rerun and needs the newest log in the THOR program folder (v10 `*.txt`, v11 `*.jsonl`);
it fails when logs were written elsewhere. See [diagnostics.md](diagnostics.md).

## 4. Restarting after an abort

- Fix the cause first; a rerun with the same command hits the same wall.
- Resume needs the resume flag on the interrupted run (v10 `--resume`, v11 `--resume-scan`) and identical
  arguments; see the `thor-db` skill. v10.7 stores the Filescan position reliably only for hard kills; after a
  clean stop (E, timeout, resource control, SIGTERM) the Filescan restarts from the beginning while finished
  modules are still skipped.
- Missing HTML report: `thor-util report --logfile <log>`.
