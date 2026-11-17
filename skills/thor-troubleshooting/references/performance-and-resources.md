# Performance and resources

## 1. Defaults that matter

| Setting | v10 (10.7.x) | v11 |
|---|---|---|
| Threads | `--threads` default **1**; all cores in `--lab`, `--dropzone`, `--thunderstorm`; 0 = all cores, negative = cores minus N | default = ceil(cores x cpu-limit / 100), i.e. ~70 % of cores; `--threads 0` all cores; soft mode forces 1 unless `--threads` is set |
| CPU limit (pause while **system-wide** CPU is above) | `--cpulimit`/`-c` 95, `--nocpulimit` | `--cpu-limit`/`-c` 70 (alias `--cpulimit`), `--cpu-limit 100` to disable; Windows 8+: also a hard cap on THOR's own CPU (job object) |
| Min/max CPU limit | 15-100 (clamped) | 15-100 (clamped) |
| Free-RAM floor | `--minmem 50` (MB) | `--memory-limit 50MB` (plain number = bytes) |
| File size limit | `--max_file_size` 30 MiB; intense/lab/allfiles 200 MiB **only if the value is still the default**; `0` = 1 KiB (!) | `--file-size-limit 64MB`; `--deep`/`--lab`/`--files-all` 200 MB unless set; `0` = unlimited |
| Process size limit | `--max_process_size` 2 GB (soft 500 MB) | `--process-size-limit 2GB` (soft 500 MB) |
| Priority | normal; low only with `--lowprio`/`--verylowprio` or soft mode | same (`--low-priority`, `--very-low-priority`); prefers efficiency cores on hybrid CPUs at normal intensity |
| Resource checks in deep modes | `--intense` keeps them; `--lab` disables | `--deep`/`--intense`, `--lab` disable RAM check and CPU limit |
| Memory footprint | baseline | about 40 % more than v10 (manual planning figure) |

Byte-size values: v10 accepts `KB/MB/GB/TB` suffixes on size flags (not on `--minmem`, which is MB). v11:
plain number = bytes, suffix = powers of 1024, `30M` is rejected (needs `B`). Always write a unit in v11.

## 2. Soft mode

Automatic when total RAM < 1024 MB or fewer than 2 CPUs (only at normal intensity), or with `--soft`.
Start-up Notice: `Activating soft mode due to total memory lower than 1024 MB ...` / `... due to low CPU count ...`.
Disable the automatic switch with v10 `--nosoft`, v11 `--no-soft`.

Effects: disables Mutex, Firewall, LoggedIn, NetworkSessions, NetworkShares, LsaSessions, Hosts, DoublePulsar,
executable decompression; low priority; CPU limit 70 % (v10) / 50 % (v11); process size limit 500 MB;
1 MB chunks; v11 also 1 thread and Sigma/Security-event shortcuts. Coverage is reduced: on a 1-vCPU VM
"fewer findings than on the big server" is expected.

## 3. Memory: where it goes

- Each worker thread holds the current element. v10 allocates a buffer of the full `max_file_size` for every
  archive, e-mail or Office file it opens, per thread (8 threads x 500 MB = several GB). Raising the limit
  costs memory on every host you scan.
- Logs, registry hives, EVTX, MFT, prefetch, LNK and memory dumps are parsed at any size: the file size limit
  does not decide whether those are analysed.
- `--deep`/`--intense`/`--lab`: 200 MB size limit, all files deep-scanned, v11 also no RAM guard.

Reduce memory, in this order:
1. Fewer threads (`--threads 4`).
2. Default file size limit (remove custom `max_file_size`/`file-size-limit` from `config/thor.yml`).
   v10: in `--lab`/`--intense`/`--allfiles` the limit becomes 200 MiB only while it still equals the 30 MiB
   default; any explicit `--max_file_size` is kept. Confirm with the v10 start-up line
   `Max. file size to be scanned is ... MB`.
3. `--soft` (live systems) or avoid `--deep` on endpoints.
4. Only then touch the RAM guard (`--minmem`/`--memory-limit`).

Linux: THOR warns `resource limit for <name> is low for THOR` when `ulimit -l` (memlock) < 64 KiB,
`ulimit -d` (data) < file size limit x threads, or `ulimit -n` < 20. Raise them or expect OOM failures.

## 4. Speed

| Goal | v10 | v11 |
|---|---|---|
| Use more cores (lab/analysis host) | `--threads 0` | `--threads 0` (or `--cpu-limit 100`) |
| Don't pause on a loaded host | `--cpulimit 99` / `--nocpulimit`, `--nolowprio` | `--cpu-limit 100`, `--no-low-priority` |
| Be gentle on endpoints | `-c 40`, `--soft`, `--lowprio` | `-c 40`, `--soft`, `--low-priority` |
| Recent changes only | `--quick` (3-day lookback on Filescan, skips Eventlog/EVTX/LogScan/...) | `--fast` (same idea) |
| Lookback for files | `--lookback N --global-lookback` (default lookback applies only to Eventlog) | `--lookback N --lookback-global` |
| Skip huge folders | `config/directory-excludes.cfg` (regex per line) | `--exclude-path <regex>`, `exclude-path:` in `config/thor.yml`, or `config/path-excludes.cfg` (old `directory-excludes.cfg` still read) |
| AV/EDR overhead | exclusions | exclusions |

`--quick`/`--fast` do not change threads or size limits. A low CPU limit on a permanently busy host makes
THOR pause almost all the time and finally hit the 168 h timeout.

## 5. Measuring

- Linux: `top -p <pid>`, `free -m`, `vmstat 5`; macOS: `top -pid <pid>`, `vm_stat`; Windows: Task Manager /
  `Get-Process thor64 | Select-Object CPU,WorkingSet64`.
- End of scan Info `THOR mostly idled waiting for CPU` -> CPU limit dominated the runtime.
- Element-level timing: ThorDB `stats`/`times` (`thor-db` skill), `--bulkstats`/`--statistics`
  ([diagnostics.md](diagnostics.md)).
