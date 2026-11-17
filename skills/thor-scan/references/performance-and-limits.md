# Performance, resources and limits

## Threads

| | THOR 10.7 | THOR 11 |
|---|---|---|
| Default | 1 thread | `ceil(cores x cpu-limit / 100)` = 70% of cores by default |
| Soft mode | 1 | 1 (unless `--threads`) |
| Intense / deep | 1 | all cores (deep implies no resource check -> CPU limit 100) |
| Lab, drop zone | all cores | all cores |
| `--threads 0` | all cores | all cores |
| `--threads -2` | all cores but two | same |

`--threads` works with every license (v10 since 10.7.15). Multithreaded parts: Filescan, registry, Eventlog,
ProcessCheck, drop zone. Memory grows with the thread count (each thread holds file and archive buffers).

## CPU limit

- v10 `-c, --cpulimit` (default 95, minimum 15); v11 `-c, --cpu-limit` (default 70, range 15-100).
- THOR **pauses** while the **system-wide** CPU load is above the value. v10: pause only. v11: the value also sets
  the thread count and, on Windows 8+, a hard cap on THOR's own CPU (job object).
  On a permanently busy host THOR keeps pausing and looks hung; raise `-c`, or add `--nolowprio`/`--no-low-priority`
  so THOR is not starved (manual advice for constant high load).
- v11 also derives the thread count from it: `-c 40` on 8 cores = 4 threads.
- Disable: v10 `--nocpulimit`; v11 `--cpu-limit 100` (`--no-cpu-limit` is deprecated).
- Soft mode: v10 caps at 70, v11 sets 50 (unless `-c` is given).

## Priority

v10 `--lowprio`, `--verylowprio`, `--lowioprio`, `--nolowprio`; v11 `--low-priority`, `--very-low-priority`,
`--low-io-priority`, `--no-low-priority`. Soft mode lowers the priority automatically.

## Resource control

| Item | THOR 10.7 | THOR 11 |
|---|---|---|
| Free-RAM floor (stop when free RAM falls below) | `--minmem 50` (integer **MB**) | `--memory-limit 50MB` (bare number = **bytes**) |
| Log flood guard | fixed: reduced logging after 60 MB of log, exit after 64 MB | `--log-size-limit 200MB`: reduced logging 4 MB before, cancel when exceeded; `0` = off |
| Turn off | `--norescontrol` (implied by `--lab`, `--dropzone`, `--thunderstorm`; **not** by `--intense`) | `--no-resource-check` (implied by `--deep`, `--lab`, `--dropzone`; also sets CPU limit 100 unless `-c` is given) |
| Runtime limit | `--max_runtime 168` (hours, 0 = none) | `--timeout 168` |
| Process size | `--max_process_size 2GB` (soft 500MB) | `--process-size-limit 2GB` (soft 500MB) |

`--memory-limit`/`--minmem` is a floor of free memory, not a cap on THOR's usage. THOR 11 uses about 40% more RAM
than THOR 10. Low disk space only produces a warning. Turning resource control off is for lab machines and copies;
on live production systems keep it.

## File size limit

| | THOR 10.7 | THOR 11 |
|---|---|---|
| Flag | `--max_file_size SIZE` | `--file-size-limit SIZE` (alias `--max_file_size`) |
| Default | 30 MB (`31457280` in `config/thor.yml`) | 64 MB |
| Intense/deep, lab, all files | 200 MB, but only while the limit is still the 30 MB default | 200 MB unless `--file-size-limit` is given (an explicit value is used in deep/lab too) |
| `0` | **1 KiB** (almost no file gets a content scan) | no limit |
| Above the limit | no content scan (YARA on content, hash IOCs, STIX, archive/e-mail/Office unpacking) and no hash; file name, path and header checks (filename IOCs, meta rules) still run | same |
| Always parsed regardless of size | EVTX, registry hives, log files, MFT, memory dumps (DumpScan), prefetch, LNK, scheduled tasks and other selector-driven parsers | same |
| Force the limit on those too | `--force-max-file-size` | `--enforce-file-size-limit` |

Guidance:

- **Leave the limit alone on live systems.** The large artifacts that matter (event logs, hives, logs, MFT) are
  already parsed at any size, and a raised limit costs memory on every thread. v10 reserves a buffer of the full
  limit for every archive, e-mail or Office file it opens, per thread, until the end of the scan (8 threads x 500 MB
  = several GB).
- Raise it for copies, mounted images and lab machines with spare memory (intense/deep/lab already use 200 MB).
- To keep THOR away from huge files or folders, exclude them (v10 `config/directory-excludes.cfg`, v11
  `--exclude-path`) instead of lowering the limit.
- Units: `KB/MB/GB/TB` (1024-based). In v10 a bare number is bytes for `--max_file_size` but MB for `--minmem`.
- Check the effective value in the startup line "Max. file size to be scanned is ...".

## Other limits

| v10 | v11 | Default | Meaning |
|---|---|---|---|
| `--max_log_lines` | `--log-line-limit` | 1,000,000 | lines per log file |
| `--max-recursion-depth` | `--archive-depth` | 4 | nested archives |
| `--max-nested-objects` | `--archive-file-limit` | 10,000 / 100,000 (0 in deep) | files per archive |
| `--bulk-size` | `--chunk-size` | 20 MB (intense/deep 100 MB, soft 1 MB) | data processed together |
| `--max-hits` | `--match-limit` | 10,000 / 100,000 (0 in lab) | reports per rule |
| `--yara-timeout` | same | 90 s | per YARA scan |

## Faster scans

1. Restrict scope: `-a Filescan -p DIR` for a folder; `--quick`/`--fast`; `--lookback N` with global lookback.
2. Use more threads on dedicated machines (v10 `--threads 0`; v11 raise `-c` or set `--threads`).
3. Add AV/EDR exclusions for the THOR process and folder (Defender alone adds 50-100% runtime); see `thor-troubleshooting`.
4. Exclude huge irrelevant data (backups, mail stores, database files) with path excludes.
5. Disable unneeded parts: v10 `--noarchive`, `--nologscan`; v11 `--exclude-component Archive,LogScan`.

## Risky flags on live systems

| Flag | Risk |
|---|---|
| `--intense` / `--deep`, `--allfiles` / `--files-all` | long runtime, high I/O and memory; v11 deep also drops resource control |
| `--norescontrol` / `--no-resource-check` | no free-RAM stop on production hosts |
| raised file size limit | memory per thread |
| `--alldrives` / `--all-drives` | walks network shares (long, load on file servers) |
| `--mft` / `--mft-analysis` | high memory |
| `--c2-in-memory` / `--c2-memory-analysis` | many false positives (browsers) |
| `--dump-procs` / `--process-dump` | disk usage (never dumps lsass.exe; max 10) |
| `--full-proc-integrity` / `--process-integrity-full` | false positives |

## Timing data

ThorDB keeps per-element timing of the last cleanly finished scan (not in lab mode). Interpretation: `thor-db` skill.
For a stuck element, use the CTRL+C menu (interactive) or `thor-util diagnostics`: `thor-troubleshooting` skill.
