# Stuck, frozen and slow scans

## 1. Is THOR still alive?

```sh
# Linux/macOS: PID, state and binary name only (no command lines: they can contain tokens)
ps -A -o pid=,stat=,comm= | awk '$3 ~ /^thor/ && $3 !~ /util/'
```
```powershell
Get-Process | Where-Object { $_.ProcessName -like 'thor*' -and $_.ProcessName -notlike '*util*' } |
  Select-Object Id, ProcessName, CPU, WorkingSet64, Responding
```

- Process gone -> it ended; see [scan-aborts.md](scan-aborts.md).
- State `T` (stopped/traced) on Linux, or CPU time not increasing for many minutes -> something suspends
  THOR (AV/EDR almost always).
- CPU busy but no new log lines -> long element (CTRL+C to see it) or CPU-limit pauses (see section 4).

## 2. Causes of frozen scans (manual figures)

| Cause | Share | Signal | Fix |
|---|---|---|---|
| AV/EDR suspends or inspects THOR | > 98 % | Stalls typically in Mutex, Events, NamedPipes/Pipes, ShimCache, ProcessCheck; same element each time | Exclusions, see [av-edr-interference.md](av-edr-interference.md) |
| Windows console QuickEdit mode | < 1 % | Window title starts with "Select" after a click into the console | Press Enter; disable QuickEdit in console properties; run as a task |
| Constant high system load + low priority | < 1 % | THOR gets no CPU time | v10 `--nolowprio`, v11 `--no-low-priority`; raise the CPU limit |
| Perceived stall | < 1 % | Element changes on every CTRL+C | Just slow: check disk speed and AV |

"98 %" is the share of frozen scans caused by AV/EDR, not a progress value.

## 3. CTRL+C menu

v10 (prompt in the console, needs a TTY):
```
Enter command (C to continue the scan, E to exit, X to cancel the current module):
```
Type the letter and press Enter. `X` exists only while a multithreaded module runs. Before the prompt THOR
logs `Current module` (ACTIVE_MODULE, MODULE_DURATION) and per worker `Last scanned Element` (ELEMENT,
ELEMENT_DURATION, SUBELEMENT_n). Without a TTY or with `--silent`, CTRL+C exits: "Non-interactive mode,
exiting." (exit 1, no HTML report).

v11 (TUI): the overlay shows `[C] Continue  [E] Exit  Up/Down: Prev/Next Item  [Del/x]: Cancel`.
`C` continues, `E`/`Q` exits, `k`/`j` or arrows select a task, `Del`/`x` cancels the selected task and its
subtasks. **A second CTRL+C while the menu is open exits THOR** ("THOR was terminated by user request.").
Without the TUI (`--no-tui`, output redirected, `--silent`) or with `kill -INT`, THOR exits at once:
"Received interrupt signal, exiting."

Reading the result:

| Observation over 2-3 checks, ~30 min apart | Meaning | Action |
|---|---|---|
| Same element, duration grows | THOR stuck on this file/process/log | Exclude it, or cancel the task (v11) / module (v10 `X`) |
| Same folder, different files | Huge folder (mail store, cache, backups) | Exclude the folder |
| Something new every time | Scan is progressing slowly | Disk speed, AV/EDR, CPU limit |
| CTRL+C itself not handled | Process suspended | AV/EDR; collect `thor-util diagnostics` |

## 4. Slow but moving

| Cause | Check | Fix |
|---|---|---|
| CPU limit pauses THOR while **system-wide** CPU is above the limit (v10 default 95 %, v11 70 %) | Info `THOR recently mostly idled waiting for CPU` (on CTRL+C) or `THOR mostly idled waiting for CPU` (at exit) | Raise v10 `--cpulimit 99` / disable `--nocpulimit`; v11 `--cpu-limit 100` (`--no-cpu-limit` is deprecated) |
| v10 runs 1 thread by default | `--threads` not set | `--threads 0` (all cores) or a number; available with every license since 10.7.15 |
| v11 thread count follows the CPU limit (about 70 % of cores) | | `--threads N`; soft mode forces 1 thread unless `--threads` is set |
| Soft mode active (1 CPU or < 1024 MB RAM, or `--soft`) | Notice `Activating soft mode due to ...` | Expected on small VMs; v10 `--nosoft`, v11 `--no-soft` if the host can take it |
| Huge element (EVTX, hive, mailbox, archive, VM disk) | CTRL+C | Exclude it; logs, hives and EVTX are parsed at any size (the file size limit does not apply) |
| Network / slow storage | Mounted share or USB disk | Copy evidence locally, or run THOR on the file server |
| AV/EDR on-access scanning every file THOR reads | Defender: +50 to 100 % runtime without exclusion | Exclude THOR process and folder |
| `--deep` / `--intense` / `--lab` / `--files-all` | Every file deep-scanned, 200 MB size limit | Use default intensity for live endpoints |

Bottleneck data after the fact: ThorDB `stats` table (per module, per scan root, directories down to depth 2 or
taking >= 20 s) and `times` table (deep-scan selectors, bulk rules, v11 hooks). Use the `thor-db` skill.
The "Maximum runtime has been exceeded" message also lists the elements in progress.

## 5. Stuck during startup

| Last line before the stall | Cause | Fix |
|---|---|---|
| Signature initialisation (YARA/Sigma compile) | Large custom rule sets, YARA Forge `full`, slow disk | Wait; check rule count with v10 `--print-signatures` / v11 `--list-signatures` |
| Lab/Trial license prompt waiting for a 3-digit response | Non-host-bound lab/trial license needs interactive challenge | Run interactively once or use a host-bound license |
| Nothing at all on Windows | AV/EDR blocks the binary | Check the AV/EDR console and quarantine |

## 6. After a hang: continue where it stopped

Resume is ThorDB based and only works if the interrupted run was started with the resume flag:
v10 `--resume`, v11 `--resume-scan`, and the next run uses the same scan flags. `--lab`, Dropzone and
(v11) HTTP-server mode have no ThorDB, so no resume. Only modules already finished and the Filescan
position are skipped; small gaps (re-scanned or skipped elements) are by design. Details: `thor-db` skill.

Disabling ThorDB (v10 `--nothordb`, v11 `--no-thordb`) does not delete resume state; it only ignores the DB
for that run. To drop resume state, run once without the resume flag, or point v10 `--dbfile` / v11
`--thordb-path` at a new **file**.

## 7. Evidence to keep before killing THOR

1. CTRL+C output (element, duration) or a screenshot.
2. `thor-util diagnostics --output diag.zip` from a second shell while THOR still runs.
3. The partial log (filtered as in SKILL.md before showing it).
4. For AV/EDR: product, version, policy, and the product's own event for THOR.
