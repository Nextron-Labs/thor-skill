# Scan modes

Intensity order: Soft < Default (Normal) < Intense/Deep. Lab, drop zone and Thunderstorm are special modes built on top
of intense/deep. Mode effects below are verified against THOR 10.7 and THOR 11 builds; the manuals are partly stale.

## Overview

| | Soft | Default | Quick / Fast | Intense / Deep | Lab |
|---|---|---|---|---|---|
| v10 flag | `--soft` | none | `--quick` | `--intense` | `--lab` |
| v11 flag | `--soft` | none | `--fast` (alias `--quick`) | `--deep` (alias `--intense`) | `--lab` |
| Modules | all except Mutex, Firewall, LoggedIn, NetworkSessions, NetworkShares, LSASessions, Hosts | all for the OS, MFT off | all except Eventlog, Firewall, UserDir/profiles, Hotfixes, MFT | all, MFT on | Filescan only (+ Artifact Collector with `--collector`) |
| Features off | DoublePulsar, EXE decompression | none | LogScan, EVTX | none | none |
| Files deep-scanned | interesting types only | interesting types only (extension or magic header, DEEPSCAN rules) | same, but only files changed in the last 3 days (plus ~40 high-risk dirs) | **every file** | every file |
| File size limit | v10 30 MB / v11 64 MB | v10 30 MB / v11 64 MB | same as default | 200 MB unless set | 200 MB unless set |
| Built-in path/registry excludes | on | on | on | off | off |
| Resource control (free RAM floor, log flood guard) | on | on | on | v10 **on**; v11 **off** (`--deep` implies `--no-resource-check`) | off |
| CPU limit | v10 70%; v11 50% | v10 95%; v11 70% | same as default | v10 95%; v11 100% unless `-c` | v10 95% (CPU limit feature stays); v11 100% unless `-c` |
| Threads | v10 1; v11 1 | v10 1; v11 ceil(cores x 70%) | same as default | v10 1; v11 all cores | all cores |
| Priority | low (unless `--nolowprio`/`--no-low-priority`) | normal | normal | normal | normal |
| Sigma threshold | high | high | high | medium | medium |
| Reasons shown per finding | 2 | 2 | 2 | all | all |
| ThorDB | on | on | on | on | **off** (no resume, no delta, no timing data) |
| Other | process size limit 500 MB, chunk 1 MB | | lookback applies to Filescan only | memory-dump files analysed, process integrity (Windows), archive file limit 0 (v11) | all drives unless `-p`; match limit 0; no scan lock; cross-platform IOC paths; v11: references only via `--path-remap` |
| License | any | any | any | any | lab-type |

Thread count without `--threads` in v11 is `ceil(cores x cpu-limit / 100)`, so `-c 50` also halves the threads.

## Auto-soft

THOR switches to soft mode at Normal intensity when the system has fewer than 2 CPUs or less than 1024 MB RAM
(log: "Activating soft mode due to ..."). Prevent with `--nosoft` (v10) / `--no-soft` (v11). Intense/deep and lab are
never auto-softened.

## Combinations

| Combination | THOR 10.7 | THOR 11 |
|---|---|---|
| `--soft` + `--intense`/`--deep` or `--lab` | soft silently wins (lab becomes a soft scan) | exit 1: "... are incompatible" |
| `--soft` + `--norescontrol`/`--no-resource-check` | allowed | exit 1 |
| `--soft` + `--diff`/`--delta` | fine (follow-up on fragile systems) | fine |
| `--lab` + `--intense`/`--deep` | redundant, harmless | redundant, harmless |
| `--lab` + `--quick`/`--fast` | quick silently disabled | fast silently disabled |
| `--lab` + `-a X` | `-a` ignored (Filescan only) | only X that is Filescan survives |
| `--lab` + `-m`/`--memory-dump-file` | works, but `--lab` adds nothing (image mode replaces the module set) | **nothing runs**: don't combine |
| `--lookback N` + `--diff`/`--delta` | allowed | exit 1: "mutually exclusive" |
| `--quick` + `--intense` | both apply (odd, not refused) | both apply |
| `--threads N` with `--lab` | honoured | honoured |

## Lookback and delta

- `--lookback N`: only elements created/modified within N days. Default module list:
  v10 Windows `Eventlog`, v10 Linux/macOS **empty** (so `--lookback` alone restricts nothing), v11 `Eventlog`.
- Extend to Filescan, Registry, Services, hives, EVTX: v10 `--global-lookback`, v11 `--lookback-global`.
  Pick modules explicitly: v10 `--lookback-modules`, v11 `--lookback-module`.
- High-risk APT directories ignore lookback unless v10 `--force-aptdir-lookback` / v11 `--lookback-aptdirs`.
- `--diff` (v10) / `--delta` (v11): per-module lookback from the last completed scan in ThorDB. Needs ThorDB
  (not with lab, `--nothordb`/`--no-thordb`). Both lookback and delta trust timestamps: timestomped files are missed.
- `--quick`/`--fast` sets a 3-day lookback on Filescan unless `--lookback` is given (v11 manual text "two days" is wrong).

## Choosing a mode

| Situation | Mode |
|---|---|
| First sweep of endpoints and servers | default |
| Weak hardware, VDI, critical servers | `--soft`, or default with `-c 50` |
| Time-boxed triage | `--quick` / `--fast`, or `--lookback 7` with global lookback |
| Follow-up sweep after a baseline | `--diff` / `--delta` |
| Copy, mounted image, extracted files on a lab machine | `--lab` (license) or the lab-less combination in [forensic-lab.md](forensic-lab.md) |
| Single suspicious folder on a live host | `-a Filescan -p DIR` (add `--intense`/`--deep` only on a non-production host) |
| Pure YARA test of a rule set | `--pure-yara -a Filescan -p DIR` (no Sigma, no STIX, most parsers off) |
