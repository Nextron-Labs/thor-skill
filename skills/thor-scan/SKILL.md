---
name: thor-scan
description: Builds exact, safe THOR and THOR Lite scan command lines for THOR 10.7 and THOR 11 on Windows, Linux and macOS (thor64.exe, thor-linux-64, thor-macosx, thor64-lite.exe, thor-lite-linux-64). Use when the user wants to scan a live host, a single directory, a mounted disk image (--lab, --virtual-map, --path-remap, --target-os, -j), a memory dump (-m, --image_file, --memory-dump-file), an SSHFS-mounted appliance, a file share or NAS, or many folders, or asks which scan mode (--soft, --quick/--fast, --intense/--deep, --lab), output flag (-e, --jsonfile, --json, --text, --audit-trail), thread, CPU or file size setting (--threads, --cpulimit, --max_file_size, --file-size-limit) or exclude to use.
compatibility: THOR 10.7.x and THOR 11.0 (Tech Preview / release candidates), full and Lite editions. Commands differ per version; detect it first.
metadata:
  author: Nextron Systems
  version: "2.0"
---

# THOR scan command builder

Goal: one correct, version-native, safe command for the user's target, with a short rationale and
"if it fails" checks. The `thor` skill holds the global rules (license-owner filtering, no unrestricted
test scans, evidence safety), the binary table and the full v10/v11 flag map. Follow them.

## Preflight (read-only)

1. List the THOR folder; pick the binary for OS and edition (`thor64.exe`, `thor-linux-64`, `thor-macosx`;
   Lite: `thor64-lite.exe`, `thor-lite-linux-64`, `thor-lite-macosx`).
2. `<binary> --version` -> `THOR 10.7.x` or `THOR 11.x`. Never mix flag spellings across versions.
3. Edition: `lite` in the binary name -> also load the `thor-lite` skill (no lab features).
4. License, only if the plan needs a lab-gated flag (`--lab`, `-j`, `--virtual-map`/`--path-remap`, `-m`,
   `--alldrives`/`--all-drives`, `--nodoublecheck`/`--no-scan-lock`, `--dropzone`): v11 `--list-licenses --lab`,
   v10 tiny run; redact the owner (commands in the `thor` skill). Lab-type = Forensic Lab, Incident Response, Trial.
   Unbound Lab/Trial licenses prompt for 3 digits, so they cannot run unattended.
5. Target type and OS of the target (for images), where output may be written (never onto evidence), and
   whether the host is a fragile production system.

## Hard rules

- Repeat `-p` for every path (`-p A -p B`); v11 also accepts `--path A,B`. Never `-p A B`.
- Never place a value after a boolean flag (`--lab /mnt/x` fails). Optional-value flags need `=`:
  v10 `--jsonfile=F`, `--stats-file=F`; v11 `--stats-csv=F`, `--audit-trail=F`.
- Always set an output directory with `-e` (`--rebase-dir` v10, `--output-directory` v11).
- `--lab` always with `-p` (otherwise it scans all drives). `--lab` already implies intense/deep, no resource
  control, all cores, no ThorDB and Filescan only: don't add `--intense`, `--quick`, `-a`, `--alldrives`.
- v11 exits 1 for: `--soft` with `--deep`/`--lab`/`--dropzone`/`--no-resource-check`; `--lookback` with `--delta`;
  a `--path-remap` whose original side has another OS's path style unless `--target-os` matches.
- v10 silently lets `--soft` override `--intense`/`--lab`. Never combine them.
- v11: never combine `--lab` with `--memory-dump-file` (both deactivate the other's module; nothing runs).
- Test runs: small `-p`, `-a Filescan`, explicit `-e`, ThorDB off (`--nothordb` v10 / `--no-thordb` v11).
- Live production endpoints: default or soft mode only. `--intense`/`--deep` and `--lab` are for copies,
  mounted evidence and lab machines.

## Decision table

`OUT` = output folder, `HOST` = original host name. Short flags `-p -a -e -j -m -c` are identical in both versions.

| Target | THOR 10.7 | THOR 11 |
|---|---|---|
| Live Windows host (sweep) | `thor64.exe -e C:\thor-out` | same |
| Live Windows, all local disks | `thor64.exe --allhds -e C:\thor-out` | `thor64.exe --all-hard-drives -e C:\thor-out` |
| Live Linux host | `sudo ./thor-linux-64 -e /var/tmp/thor-out` | same |
| Live macOS host (Full Disk Access for the terminal) | `sudo ./thor-macosx -e /var/tmp/thor-out` | same |
| Busy or fragile production server | add `--soft` or `-c 50` | add `--soft` (50% CPU, 1 thread) or `-c 50` |
| One directory only (live) | `thor64.exe -a Filescan -p C:\inetpub -e C:\thor-out` | same (`--module`/`--path` long forms) |
| Mounted Windows image on Windows (lab) | `thor64.exe --lab -p S:\ --virtual-map S:C -j HOST -e C:\cases\out` | `thor64.exe --lab -p S:\ --path-remap S:C --target-os Windows -j HOST -e C:\cases\out` |
| Mounted Windows image on Linux/macOS (lab) | `./thor-linux-64 --lab -p /mnt/img --virtual-map /mnt/img:C -j HOST -e /cases/out` | `./thor-linux-64 --lab -p /mnt/img --path-remap /mnt/img:C --target-os Windows -j HOST -e /cases/out` |
| Mounted Linux image on Linux (lab) | `./thor-linux-64 --lab -p /mnt/img --virtual-map /mnt/img:/ -j HOST -e /cases/out` | `./thor-linux-64 --lab -p /mnt/img --path-remap /mnt/img:/ --target-os Linux -j HOST -e /cases/out` |
| Mounted image, no lab license (or Lite) | `./thor-linux-64 -a Filescan --intense --norescontrol --cross-platform --threads 0 --nothordb -p /mnt/img -e /cases/out` | `./thor-linux-64 --module Filescan --deep --cross-platform-paths --no-thordb -p /mnt/img -e /cases/out` (+ `--target-os Windows` for a Windows image on Linux) |
| Memory dump (raw, crash dump, LiME/AVML) | `./thor-linux-64 -m /cases/mem.raw -j HOST -e /cases/out` | `./thor-linux-64 --memory-dump-file /cases/mem.raw -j HOST -e /cases/out` |
| Volatility-extracted process dumps | `--lab -p /cases/procs -e /cases/out` (no lab: `-a Filescan --intense -p ...`) | `--lab -p /cases/procs -e /cases/out` (no lab: `--module Filescan --deep -p ...`) |
| SSHFS-mounted appliance (read-only, data dirs only) | `./thor-linux-64 -a Filescan -p /mnt/app/var/www -e /cases/out` (Linux host; FUSE is scanned) | needs a lab-type or Lite license (sshfs counts as network FS): `--lab -p /mnt/app/var/www --path-remap /mnt/app:/ --target-os Linux -j HOST -e /cases/out` |
| File share / NAS | Run THOR on the file server if supported. Else (lab): `thor64.exe -a Filescan --alldrives --threads 0 -p X:\ -p Y:\ -e C:\thor-out` | `thor64.exe --module Filescan --all-drives --threads 0 -p X:\ -p Y:\ -e C:\thor-out` |
| Many folders | repeat `-p`; `-p C:\dir:NOWALK` = no recursion | repeat `-p` or `--path "A,B"` |

Memory dumps: lab-type license (or the `allowdeepdive` special); THOR Lite 10.7.30+ also accepts `-m`; THOR Lite 11
cannot scan dumps. `-j` needs a lab-type license: drop it otherwise. Do not run DeepDive on `hiberfil.sys` or
compressed dumps; convert to raw first. Details: [references/forensic-lab.md](references/forensic-lab.md).

## Scan modes (what each changes)

| Mode | v10 flag | v11 flag | Effect |
|---|---|---|---|
| Soft | `--soft` | `--soft` | Drops Mutex, Firewall, LoggedIn, NetworkSessions, NetworkShares, LSASessions, Hosts, DoublePulsar, EXE decompression; low priority; process size 500 MB; v10 CPU cap 70%; v11 CPU 50% and 1 thread. Auto-on with < 2 CPUs or < 1024 MB RAM (`--nosoft`/`--no-soft` prevents) |
| Default | none | none | All modules for the OS except MFT; resource control on; v10 1 thread, CPU 95%; v11 threads = 70% of cores |
| Quick / Fast | `--quick` | `--fast` | Filescan only looks at files changed in the last 3 days (about 40 high-risk dirs fully); drops Eventlog, EVTX, LogScan, Firewall, user profiles, Hotfixes, MFT |
| Intense / Deep | `--intense` | `--deep` | Every file deep-scanned, built-in excludes off, file size limit 200 MB, MFT, memory-dump files, process integrity, Sigma threshold medium, all reasons. v10 keeps resource control and 1 thread; v11 implies `--no-resource-check` and all cores |
| Lab | `--lab` | `--lab` | Filescan only, intense/deep, all drives unless `-p`, no ThorDB, no resource control, all cores, cross-platform IOC paths, no match limit, no scan lock. v11: file references only via `--path-remap`. Lab-type license |
| Delta | `--diff` | `--delta` | Only elements changed since the last completed scan (ThorDB required) |
| Lookback | `--lookback N --global-lookback` | `--lookback N --lookback-global` | v10 Linux/macOS: `--lookback` alone does nothing; v11: alone = Eventlog only |

Details and combinations: [references/scan-modes.md](references/scan-modes.md).

## Output

| Need | v10 | v11 |
|---|---|---|
| Output folder | `-e DIR` | `-e DIR` |
| JSON | `--jsonfile=DIR/HOST.json` (`--jsonv2` = simpler schema) | written by default (`.jsonl`, v3) |
| Text log | written by default | `--text <hostname>_thor_<time>.txt` |
| Forensic audit trail (all elements, for THOR Lens) | `--audit-trail /abs/path/HOST_audit.json.gz` (experimental) | `--audit-trail` (default name, in `-e`) |
| Syslog/SIEM | `-s siem:514:JSON:TCP` | same |
| UTC timestamps | `--utc` | `--timestamp-utc` |
| Fewer files | `--nohtml --nocsv` | `--no-html --no-csv` |

Placeholders: v10 `:hostname:`/`:time:`, v11 `<hostname>`/`<time>`. More: [references/output.md](references/output.md).

## Performance and limits (short)

- Threads: v10 default 1 (`--threads 0` = all cores, `-2` = all but two); v11 default ceil(cores x 70%).
- `-c N` pauses THOR while **system-wide** CPU is above N%. v10: pause only. v11: also sets the thread count and,
  on Windows 8+, a hard cap on THOR's own CPU (job object).
- File size limit (v10 30 MB, v11 64 MB): **leave it alone on live systems.** EVTX, hives, logs, MFT, prefetch and LNK
  are parsed at any size; filename IOCs and meta rules see every file. Raising it costs memory per thread
  (v10 reserves a limit-sized buffer per archive, e-mail or Office file per thread). v10 `--max_file_size 0` = 1 KiB.
- Free-RAM floor: v10 `--minmem 100` (MB); v11 `--memory-limit 100MB` (unit required).
- Details: [references/performance-and-limits.md](references/performance-and-limits.md).

## Selection and excludes (short)

- `-p` limits only the file-system walk; add `-a Filescan` for a pure path scan.
- v11 `--exclude-path REGEX` (case-insensitive, matches the **local** path, CSV list), `--exclude-component NAME`;
  v10 `config/directory-excludes.cfg` and `--no<module>` flags.
- Network file systems are skipped unless `--alldrives`/`--all-drives`; v11 also treats Linux FUSE (sshfs, ntfs-3g)
  as network and auto-enables all-drives for a single network `--path` (license check applies).
- `$` and `%` in `-p` values are expanded as environment variables (`C:\$Recycle.Bin` breaks in v10; scan the parent).
- `--init-selector`/`--init-filter` (v11 `--signature-include`/`--signature-exclude`) match substrings of rule names,
  tags and descriptions; broad words drop many rules. False positives belong in `config/false_positive_filters.cfg`.
- Details: [references/selection-and-excludes.md](references/selection-and-excludes.md).

## Answer format

1. One recommended command (single line, native flags of the detected version).
2. Two to six bullets: why each non-obvious flag is there.
3. "If it fails": the two or three most likely causes with the next check.

Typical failure causes to cover:

| Symptom | Check |
|---|---|
| Exit 1 right after start, license list printed | lab-gated flag without lab-type license; workstation license on a server; expired license |
| "unknown flag" | v11 spelling on v10 or vice versa; see the flag map in the `thor` skill |
| "Positional arguments specified" | `-p A B`, value after a boolean flag, missing `=` |
| Finishes in seconds, nothing found | path skipped as network/FUSE/`/Volumes` (v10 macOS) file system; wrong `-p`; v10 nonexistent path exits 0 |
| "rejects the remapping" / target OS mismatch (v11) | add `--target-os Windows` or `Linux` matching the original side |
| Stops with resource control / memory messages | `--norescontrol`/`--no-resource-check` for lab copies, or raise RAM; see `thor-troubleshooting` |

## References and examples

| File | Read when |
|---|---|
| [references/scan-modes.md](references/scan-modes.md) | Exact mode effects, combinations, lookback/delta, auto-soft |
| [references/forensic-lab.md](references/forensic-lab.md) | `--lab`, remapping, `--target-os`, `-j`, memory dumps, Volatility, drop zone, collector, lab without license |
| [references/performance-and-limits.md](references/performance-and-limits.md) | Threads, CPU limit, priorities, file size limit, memory, runtime, parallel lab scans |
| [references/output.md](references/output.md) | Output files, JSON/text/HTML/CSV, audit trail, syslog, naming, encryption |
| [references/selection-and-excludes.md](references/selection-and-excludes.md) | Paths, drives, file-system classes, modules/components, excludes, signature selection, path parsing gotchas |
| [examples/windows-live-scan.md](examples/windows-live-scan.md) | Windows endpoint and server sweeps |
| [examples/linux-mounted-image.md](examples/linux-mounted-image.md) | Disk images on a Linux forensic workstation |
| [examples/macos-scan.md](examples/macos-scan.md) | macOS live scans and images on a Mac |
| [examples/memory-dump.md](examples/memory-dump.md) | Memory dumps, DeepDive, Volatility workflows |
| [examples/sshfs-remote-scan.md](examples/sshfs-remote-scan.md) | Appliances and unsupported systems via SSHFS |
| [examples/file-server-and-shares.md](examples/file-server-and-shares.md) | File servers, NAS, UNC paths, many folders |

Related skills: `thor` (identification, licenses, flag map), `thor-lite`, `thor-troubleshooting`,
`thor-custom-signatures`, `thor-deployment` (many hosts), `thor-log-analysis` (results).
