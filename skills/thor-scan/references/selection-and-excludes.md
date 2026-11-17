# Selecting what THOR scans: paths, drives, modules, excludes, signatures

## Paths

- `-p PATH` (both versions) sets the Filescan roots. **Repeat it** for several paths. v11 also takes a CSV list
  (`--path "D:\web,E:\apps"`).
- Append `:NOWALK` to scan a folder without recursion: `-p C:\Windows\Temp:NOWALK`.
- Without `-p`: Windows scans the system drive only (v10 `C:\`, v11 `%SYSTEMDRIVE%\`); other partitions only when
  artifacts point there. Add `--allhds` (v11 `--all-hard-drives`) for all local disks. Unix scans `/` with all local mounts.
- `-p` limits **only** the file-system walk (and MFT/Timestomp, which follow the roots). Process, registry, eventlog,
  autoruns and the other modules still run. For a pure folder scan add `-a Filescan` (v11 `--module Filescan`).
- v10.7: a nonexistent `-p` path exits 0 with nothing scanned. Check the path first.

### Path parsing gotchas

| Gotcha | Effect | Fix |
|---|---|---|
| `-p A B` | "Positional arguments specified" (exit 1) | `-p A -p B` |
| Comma in a path (v11) | split into two paths (CSV parsing of `--path`, `--path-remap`, `--exclude-path`) | CSV-quote: `--path "\"D:\data,old\""` |
| `$` or `%` in a path | expanded as environment variable: v10 turns `C:\$Recycle.Bin` into `C:\.Bin` | scan the parent folder, or set `Recycle='$Recycle'` in THOR's environment; current v11 builds keep paths that exist literally |
| Unix shell | `$...` expanded by the shell before THOR sees it | single-quote such paths |
| Trailing backslash before a quote on Windows (`"D:\data\"`) | the quote is escaped by the C runtime | drop the trailing backslash |

## File system classes (what is skipped without asking)

| Mount type | v10 Linux | v10 macOS | v10 Windows | v11 (all) |
|---|---|---|---|---|
| Local disks | scanned | scanned | scanned | scanned |
| USB / removable | scanned | under `/Volumes/`: skipped | scanned | scanned (macOS `/Volumes` scanned) |
| NFS, SMB/CIFS, AFS, Ceph, 9p, GPFS | skipped | skipped | network drives and UNC skipped | skipped |
| FUSE (sshfs, ntfs-3g, dissect `target-mount`) | **scanned** | sshfs skipped | n/a | **skipped** on Linux (treated as network), sshfs skipped on macOS |
| iCloud/OneDrive `~/Library/CloudStorage` | n/a | skipped | n/a | skipped |
| /proc, /sys and other pseudo FS | skipped | skipped | n/a | skipped |

Lift the skip with `--alldrives` (v10) / `--all-drives` (v11): allowed with a lab-type license, a THOR Lite license
or the `allownetworkscan` special; `--lab` sets it. v11 enables `--all-drives` automatically when exactly one `--path`
is on a network-class mount, which makes a Server/Workstation license fail the check.
Log hints: v10 "Skipping file/directory due to filesystem type", v11 "Skipping path on network share. With --alldrives ...".

## Modules and components

- Run only some modules: `-a NAME` (repeat or comma list), e.g. `-a Filescan`, `-a ProcessCheck -a Autoruns`.
  v11 names are case-insensitive (`Filescan`, `ProcessCheck`, `RegistryChecks`, `Eventlog`, `Autoruns`, `ServiceCheck`,
  `ScheduledTasks`, `Mutex`, `Pipes`, `MFT`, `Rootkit`, `Users`, `UserDir`, ...).
- Disable: v10 `--no<name>` flags (`--noprocs`, `--noreg`, `--noeventlog`, `--nologscan`, `--noevtx`, `--noarchive`,
  `--nosigma`, `--noyara`, `--nostix`, `--nothordb`); v11 `--exclude-component ProcessCheck,RegistryChecks,LogScan,Archive`
  (old flags still work but are deprecated).
- Windows: `--mft` / `--mft-analysis` (MFT module, memory-heavy; default only in intense/deep), `--ads` /
  `--alternate-data-streams`, `--wsl` (WSL distributions), `--eventlog-target NAME` (`-n`, specific logs; `all`).
- Domain controllers automatically skip Users, UserDir, NetworkSessions, LoggedIn and the registry hive feature.

## Excludes

| Purpose | THOR 10.7 | THOR 11 |
|---|---|---|
| Path | `config/directory-excludes.cfg` (one regex per line) | `--exclude-path REGEX` (repeat or CSV) and/or `config/path-excludes.cfg` (old name still read) or `exclude-path:` list in a template |
| Registry key | `config/registry-excludes.cfg` | `--exclude-registry-key REGEX` (key path without hive root) or the same file |
| Event log | `config/eventlog-excludes.cfg` | `--exclude-eventlog REGEX` (log name) or the same file |
| Process | `config/process-excludes.cfg` | `--exclude-process REGEX` (name, image path, command line) or the same file |
| Built-in stability excludes | on; off in intense/lab | on; off with `--deep`, `--files-all`, `--lab` or `--no-builtin-path-excludes` |
| False positives (output only) | `config/false_positive_filters.cfg` | same |

Path exclude rules (v11): case-insensitive regex, matched anywhere in the full path (anchor with `^`/`$`), against the
**local** path (both `/` and `\` forms), never the remapped original path. Excluded directories are not read at all;
processes whose executable is excluded are skipped too. Escape regex characters: `\\IBM\\temp_tools\\`, `\.nsf$`,
`^/mnt/remote/(proc|sys|dev|run)/`. A regex with a comma needs CSV quoting on the command line.

`false_positive_filters.cfg`: one regex per line matched against the full log message; it hides lines, it does not skip
scanning. Write the escaped rule name or path, nothing else.

## Signature selection

| Purpose | THOR 10.7 | THOR 11 |
|---|---|---|
| Load only matching signatures | `--init-selector WORD[,WORD]` | `--signature-include WORD` |
| Drop matching signatures | `--init-filter WORD[,WORD]` | `--signature-exclude WORD` |
| Only custom signatures | `--customonly` | `--custom-signatures-only` |
| Sigma minimum level | `--minimum-sigma-level high` | `--sigma-threshold high` (informational, low, medium, high, critical) |
| Sigma rule sets | n/a | `--sigma-ruleset core\|core+\|core++\|emerging_threats\|threat_hunting\|all` |
| Disable a signature type | `--nosigma`, `--noyara`, `--nostix` | `--exclude-component Sigma`, `Yara`, `Stix` |
| List loaded signatures | `--print-signatures` | `--list-signatures` |
| Show deep-scan selection logic | n/a | `--list-deepscan-criteria` |

Include/exclude match substrings of rule name, tags and description. `--init-filter AutoIt` drops every rule that merely
mentions AutoIt, including hack-tool detections. For false positives use `false_positive_filters.cfg`, a narrow rule-name
filter, or a negative-score IOC (`thor-custom-signatures`).

Example, sweep only for one incident's custom indicators across many hosts: v10 `--customonly -e OUT`,
v11 `--custom-signatures-only -e OUT`. Custom signature formats and folders: `thor-custom-signatures` skill.

## Why a file was not content-scanned

By default (not intense/deep/lab) THOR deep-scans only files whose extension or magic header looks relevant,
or that a `DEEPSCAN` meta rule selects. Options: `--intense`/`--deep` or `--allfiles`/`--files-all` (all files);
a custom YARA meta rule tagged `DEEPSCAN` for a custom type; check with `--debug --printall` (v10) /
`--debug --print-files` (v11) on a small path, which logs "Skipping deeper file scan" or "Skipping file due to file size".
