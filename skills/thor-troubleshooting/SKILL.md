---
name: thor-troubleshooting
description: Diagnoses THOR 10 and THOR 11 scans that hang, crawl, stop early, finish suspiciously fast, miss expected detections, write no output files, or fail with license or update errors. Maps symptom to likely cause to the next command; covers the CTRL+C menu, AV/EDR exclusions (Defender Add-MpPreference), resource control (--minmem/--memory-limit), timeouts (--max_runtime/--timeout), exit codes, --debug/--trace/--printall/--print-files, thor-util diagnostics and pprof, and what to send to support. Use when users say THOR is stuck, frozen, slow, killed, "exit code 1", "Rescontrol", "Maximum runtime has exceeded", "No valid license file found", "The current license type doesn't allow", "no alerts", "no .txt log", "Skipping file due to file size", "diagnostics.zip" or "heap.pprof".
compatibility: THOR 10.7.x and THOR 11 (Tech Preview / release candidates), full and Lite editions. Helper script needs a POSIX shell.
metadata:
  author: Nextron Systems
  version: "2.0"
---

# THOR troubleshooting

Goal: name the most likely cause fast and give the smallest next step. Never guess flags: v10 and v11
spell many of them differently, and unknown flags are fatal in both.

## 1. First minute

1. **Detect the version** before giving commands.

   | Cue | v10 (10.7.x) | v11 |
   |---|---|---|
   | `--version` / banner | `THOR 10.7.x` | `THOR 11.x` |
   | Default log | `<host>_thor_<time>.txt` | `<host>_thor_<time>.jsonl` (text only with `--text`) |
   | Console | plain log lines, `Enter command (C ... E ...)` prompt on CTRL+C | full-screen TUI |
   | ThorDB | `thor10.db` | `thor.db` |

2. **Ask only for what is missing:** OS, THOR version + edition (full/Lite), the exact command line (mask
   tokens/passwords), what "stuck" means (no progress / no output / stopped / too fast), last 40 log lines.
3. **Privacy:** never show lines containing `LICENSE_OWNER`, `License file found` or (v11 JSON)
   `Scan Information` (licensee name/e-mail).
   ```sh
   tail -n 40 HOST_thor_TIME.txt   | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'  # v10
   tail -n 40 HOST_thor_TIME.jsonl | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information' \
     | jq -r '[.meta.time,.meta.level,.meta.module,.message]|@tsv'                               # v11
   ```
   PowerShell: `Get-Content F -Tail 40 | Select-String -NotMatch 'LICENSE_OWNER|License file found|Scan Information'`
4. **Reproduce small:** never start a full-system scan "to test". Restrict with `-p <dir>` (+ `-a Filescan`),
   set an output directory (v10 `-e`, v11 `--output-directory`), and keep the user's DB untouched
   (v10 `--nothordb`, v11 `--no-thordb`). Never run `--lab` without `-p`.

## 2. Symptom -> cause -> next step

| Symptom | Likely causes (most likely first) | Next step | Ref |
|---|---|---|---|
| Scan hangs or crawls | AV/EDR suspends or inspects THOR (manual: >98 % of frozen scans); Windows QuickEdit (console paused after a click); CPU limit pausing on a busy host; slow network/huge element | Exclude THOR in AV/EDR (Defender: `Add-MpPreference -ExclusionProcess 'C:\thor\thor64.exe'`); press Enter in the console; CTRL+C to see the current element; no exclusion possible -> `--soft` | [stuck](references/stuck-scans.md), [AV/EDR](references/av-edr-interference.md) |
| Stuck on one element | Huge log/hive/archive/mailbox, AV/EDR holding that file or process | CTRL+C, read element + duration, continue, repeat in 30 min; same element -> exclude it (v10 `config/directory-excludes.cfg`, v11 `--exclude-path` / `config/path-excludes.cfg`) | [stuck](references/stuck-scans.md) |
| Ends early, exit code 1 | Resource control (free RAM < limit), log size limit, 168 h timeout (also in lab mode), CTRL+C/SIGTERM/shutdown, crash/panic | Read the last Error lines (table section 4) | [aborts](references/scan-aborts.md) |
| Log just stops, no reason | External kill: AV/EDR > user > management tool > attacker; OOM killer | Same element every time -> AV/EDR; `dmesg`/Event Log; `thor-util diagnostics --run` (Windows names the killer) | [aborts](references/scan-aborts.md) |
| Very fast, nothing found | Wrong/missing path (v10 drops it silently), `$` in path expanded, exclusions match everything, network FS skipped, macOS without Full Disk Access, Windows scans only `C:` | Check "The following paths will be scanned:" line; see pitfalls | [pitfalls](references/common-pitfalls.md) |
| Expected detection missing | File above size limit, file not selected for deep scan, Sigma level threshold, `--min`, soft mode (1 CPU / < 1 GB RAM), custom rule loaded as wrong type, Lite feature set | Re-scan only that file with `--debug` + print-all flag | [missing alerts](references/missing-alerts.md) |
| Output file missing | v11 writes JSONL by default, text only with `--text`; v10 JSON only with `--jsonfile=`; output went to CWD (`C:\Windows\System32` for tasks); no HTML after a non-zero exit | See pitfalls "output" | [pitfalls](references/common-pitfalls.md) |
| License error at start | Hostname mismatch, expired, workstation license on a server, lab-only flag without lab license, Lite license with full THOR | Read REASON (redacted) | [pitfalls](references/common-pitfalls.md) |
| High RAM / host slows down | Many threads x large file size limit, v11 ~40 % more RAM than v10, `--deep`/`--lab` disable resource checks | Lower `--threads`, keep default size limit, `--soft` | [performance](references/performance-and-resources.md) |
| Update/upgrade fails or "downgraded" | No valid license in the THOR folder, proxy, plain `thor-util upgrade` installs the stable 10.7 channel | Use the `thor-maintenance` skill | - |

## 3. CTRL+C menu (live progress check)

| | v10 | v11 (TUI) |
|---|---|---|
| Shows | `Current module` + per worker `Last scanned Element` with durations | `Current module` + per worker `Worker status` (task, duration, parents) |
| Keys | type `C` + Enter = continue, `E` + Enter = exit, `X` + Enter = cancel current module (only multithreaded modules) | `C` continue, `E`/`Q` exit, Up/Down (`k`/`j`) select task, `Del`/`x` cancel selected task |
| Trap | Without a TTY (service, scheduled task, pipe): CTRL+C/SIGINT exits with "Non-interactive mode, exiting." | **A second CTRL+C while the menu is open exits THOR.** Without TUI (`--no-tui`, redirected output) or with `kill -INT`, THOR exits immediately: "Received interrupt signal, exiting." |

Procedure: CTRL+C once, note element and duration, continue (`C`), wait ~30 min, repeat. Same element ->
that element is the problem. Same folder -> too many files there. Changes each time -> just slow (disk, AV).
Never send SIGINT to probe a running scan; use `thor-util diagnostics` instead.
Windows: if the console shows "Select" in the title, QuickEdit paused it; press Enter.

## 4. How a scan ended (last Error lines)

| Last lines | Meaning | Fix |
|---|---|---|
| `Available physical memory dropped below 50 MB, stopping THOR scan ...` + 3x `Process with high memory usage` | Resource control: averaged free RAM <= limit | Free RAM / fewer threads / `--soft`; last resort v10 `--minmem 0`, v11 `--memory-limit 0` |
| `Maximum runtime has exceeded, killing THOR` (v10) / `... has been exceeded ...` (v11), lists current elements | 168 h default reached (lab mode too) | Exclude the listed elements or raise v10 `--max_runtime`, v11 `--timeout` (hours, 0 = none) |
| `Logged more than N MB, exiting THOR to prevent log flooding ...` | Log size limit (FP flood). v10 fixed 64 MB, v11 `--log-size-limit` 200MB | Find the noisy rule, add a false positive filter |
| `Received interrupt signal.` + `THOR was terminated by interrupt command.` (v10) / `... by user request.` (v11) | User pressed E/Q | - |
| `Received shutdown signal, exiting.` | SIGTERM/SIGHUP, console closed, Windows logoff/shutdown | Run detached, as a service/task |
| `THOR has paniced ...` / `Module has paniced` / Go `fatal error: out of memory` | Crash / real OOM | Send log + screenshot; `--soft`, check `ulimit -a` |
| `System has < 50 MB free RAM, can't initialize THOR` | Startup gate | Free memory |
| `THOR already running` | Scan lock (other instance or stale lock) | Wait; v10 `--nodoublecheck` / v11 `--no-scan-lock` need a lab license |
| nothing | External kill (SIGKILL, AV/EDR, OOM killer, power) | See [aborts](references/scan-aborts.md) |

Exit codes (both versions): `0` = scan completed (alerts do NOT change it), `1` = any abort or error
(license, timeout, resource control, interrupt, signal, bad flag, already running). Non-zero exits write no
"Thor Scan finished" line and **no HTML report** (rebuild with `thor-util report`). v10 exits 0 even if the
`-p` path did not exist. Automation must parse the log, not the exit code.

## 5. Debug method

1. Narrow first: one module (`-a Filescan`) and one path (`-p`) that reproduces the problem.
2. Add `--debug` (skips, timeouts, why a file was not deep-scanned). `--trace` only for short runs.
3. List every checked file: v10 `--printall`, v11 `--print-files` (alias `--printall` works).
4. Timing per element: ThorDB `stats` table of the last run (use the `thor-db` skill), or the hidden flag
   v10 `--bulkstats` / v11 `--statistics` (prints the top selector/bulk/hook times at the end; add
   v10 `--max-reasons 0` / v11 `--alert-reason-limit 0` to see more than the top 2).
5. While a scan hangs: `thor-util diagnostics` (Lite: `thor-lite-util`) from another shell, **while THOR
   still runs**. Then `go tool pprof -top cpu.pprof`, `go tool pprof -http=:8080 goroutine.pprof`.
6. Debug logs: v10 writes them into the normal `.txt`; v11 into JSONL (add `--text FILE` for a text copy).
   Debug logs are 30-200 MB; compress before sending.

Details, hidden flags and the pack contents: [diagnostics](references/diagnostics.md).

## 6. What to send to support

`--version` output, OS + architecture, exact command line (secrets masked), the diagnostics pack (hangs) or
the crash output, optionally a `--debug` log of a narrowed rerun, a screenshot of the console, the ThorDB file
for "too slow" cases. **Warn the user before sharing:** diagnostics packs and logs contain host names, paths,
findings, process lists, a THOR process memory dump (Windows), the ThorDB and license owner lines. Let the
user review and redact; never paste license lines into tickets or chats.

## 7. Helper script

`scripts/quick-env-check.sh [THOR_DIR] [OUTPUT_DIR]` (POSIX sh, Linux/macOS/AIX): CPU/RAM (predicts
automatic soft mode and the 50 MB start gate), free disk for THOR/output/ThorDB dirs, ulimits, binaries,
version, signature age, license file count (never contents), running THOR PIDs without command lines, macOS
Full Disk Access hint. Read-only. Run `sh quick-env-check.sh --help`.

## 8. References (read when)

- [references/stuck-scans.md](references/stuck-scans.md) - hang, crawl, stuck element, QuickEdit, CPU waits, resuming.
- [references/av-edr-interference.md](references/av-edr-interference.md) - exclusions per product, modules that trigger EDR, `--soft`.
- [references/scan-aborts.md](references/scan-aborts.md) - every abort reason with exact messages, exit codes, external kills.
- [references/common-pitfalls.md](references/common-pitfalls.md) - fast/empty scans, path parsing, filesystems, output files, license errors.
- [references/missing-alerts.md](references/missing-alerts.md) - why a known-bad file or event was not reported.
- [references/performance-and-resources.md](references/performance-and-resources.md) - threads, CPU limit, memory, file size limit per version.
- [references/diagnostics.md](references/diagnostics.md) - debug/trace/hidden flags, thor-util diagnostics, pprof, support pack.

Related skills: `thor-scan` (building command lines), `thor-db` (ThorDB, resume, timing tables),
`thor-maintenance` (thor-util update/upgrade), `thor-log-analysis` (reading findings), `thor-lite`.

## Output format

1. Likely causes, ranked (max 3), each with the log line or observation that supports it.
2. Next command(s) for the detected version and OS.
3. What to collect if it persists (with the privacy warning).
