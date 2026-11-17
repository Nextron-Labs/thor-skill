# File servers, NAS and many folders

## Prefer scanning on the file server itself

Run THOR locally on the file server when its OS is supported: the data are local disks (no network file system
rules, no lab license needed), and process/registry checks of the server run as well.

```bat
thor64.exe --allhds -e D:\thor-out                    # v10, all local disks
thor64.exe --all-hard-drives -e D:\thor-out           # v11
thor64.exe -a Filescan -p E:\Shares -p F:\Projects -e D:\thor-out   # only the share volumes, file checks only
```

On a busy file server add `--soft` or `-c 50`, scan outside business hours, and exclude huge archives or database
folders that are known to be irrelevant.

## Scanning shares from a separate scanner host

Network drives and UNC paths are skipped unless `--alldrives`/`--all-drives` is set, which needs a lab-type license
(Forensic Lab, Incident Response, Trial), a THOR Lite license, or the `allownetworkscan` special. Use a scanner host
with at least 2 cores and 2 GB RAM.

```bat
rem v10
thor64.exe -a Filescan --alldrives --threads 0 -p X:\ -p Y:\ -e C:\thor-out
rem v11
thor64.exe --module Filescan --all-drives --threads 0 -p X:\ -p Y:\ -e C:\thor-out
rem v11, UNC path without mapping a drive (share must be readable by the user running THOR)
thor64.exe --module Filescan --all-drives --threads 0 -p \\fileserver01\shareA -e C:\thor-out
```

- `-a Filescan` / `--module Filescan`: only the file walk; process and registry checks of the scanner host are not wanted.
- `--threads 0`: all cores (network I/O bound scans benefit from more threads).
- If THOR runs as SYSTEM (scheduled task, Management Center), mapped drives of the interactive user do not exist;
  use UNC paths and grant the computer account read access.
- v11 turns on `--all-drives` automatically when the only `--path` is on a share; a Server/Workstation license then fails.

Optional for long scans (manual recommendations):

| Need | v10 | v11 |
|---|---|---|
| Resume after timeout/abort | `--resume` on every run, same scan flags | `--resume-scan` on every run, same flags |
| No runtime limit | `--max_runtime 0` | `--timeout 0` |
| Weak scanner host | `--nosoft` | `--no-soft` |
| Only recent changes | `--lookback 8 --global-lookback` | `--lookback 8 --lookback-global` |
| Follow-up scans | `--diff` | `--delta` |
| Larger files on a lab-grade scanner | `--max_file_size 100MB` | `--file-size-limit 100MB` |
| Skip event log parsing of stored EVTX | `--noevtx` | `--exclude-component Eventlog` |

## Linux/Unix NAS exports

```bash
sudo mount -t nfs -o ro nas01:/export/projects /mnt/projects
# v10 (lab-type or Lite license for --alldrives)
sudo ./thor-linux-64 -a Filescan --alldrives --threads 0 -p /mnt/projects -e /var/tmp/thor-out
# v11
sudo ./thor-linux-64 --module Filescan --all-drives -p /mnt/projects -e /var/tmp/thor-out
```

## Many folders

- Repeat `-p` for each folder: `-p D:\web -p D:\apps -p E:\uploads`. Never `-p A B`.
- v11 also accepts one CSV list: `--path "D:\web,D:\apps"` (quote paths that contain commas: `"\"D:\a,b\""`).
- Non-recursive: `-p C:\Windows\Temp:NOWALK`.
- Very long lists: put them into a template (`-t scan.yml`, key `path:` as a YAML list) and keep the command short.

```yaml
# scan.yml (v10 --template / v11 --config); keys are long flag names
path:
  - D:\web
  - D:\apps
  - E:\uploads
module:
  - Filescan
```

```bat
thor64.exe -t scan.yml -e C:\thor-out
```

## If it fails

- Scan ends immediately with no findings: the share was skipped (no all-drives); log says "Skipping ... filesystem type"
  (v10) or "Skipping path on network share" (v11).
- Exit 1 "doesn't allow the use of --alldrives": license type; run on the file server, or use a lab-type license.
- Access denied on UNC paths: the account running THOR lacks share permissions.
