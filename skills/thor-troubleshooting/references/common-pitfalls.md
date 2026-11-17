# Common pitfalls: fast/empty scans, paths, filesystems, output files, licenses

## 1. Scan finishes fast with (almost) nothing scanned

Always check the Filescan start line first: `The following paths will be scanned: <list>`.

| Cause | Tell-tale | Fix |
|---|---|---|
| Path does not exist / not readable | v10: path silently dropped (list empty or shorter), exit 0. v11: Error `Could not scan path` | Fix the path; quote paths with spaces |
| Several paths after one `-p` | `Positional arguments specified`, exit 1 | Repeat `-p` per path (`-p C:\ -p D:\`); v11 also accepts a comma list |
| `$` or `%` in the path | v10 (and older v11 builds) expand environment variables in `--path`, hostname and output-file flags (Unix: twice): `/mnt/c/$Recycle.Bin` becomes `/mnt/c/.Bin`. Current v11 builds skip the expansion when the literal path exists. Unix shells also expand `$` unless the path is in single quotes | Single-quote the path; scan the parent folder; or set the variable to itself: `Recycle='$Recycle' ./thor-linux-64 -p '/mnt/c/$Recycle.Bin'` |
| v11: comma inside a path or regex | `--path`, `--path-remap`, `--exclude-path` are CSV lists | CSV-quote the value: `--exclude-path '"/data/a,b/.*"'` |
| Exclusion matches everything | v10 `config/directory-excludes.cfg` (v11: `config/path-excludes.cfg`, old name still read) regex like `.*` or `C:\\`; v11 `--exclude-path` (case-insensitive regex on the local path, both `/` and `\` forms; also from `config/thor.yml`) | Anchor and escape regexes; test with `--debug` (Debug `Skipping file due to custom exclude`) |
| Network filesystem skipped | v10: Info `Skipping file/directory due to filesystem type. With --alldrives, ...`; v11: Error `Skipping path on network share. With --alldrives, ...` | Run THOR on the file server, or copy locally; `--alldrives`/`--all-drives` needs a lab-class license (Lite exempt) |
| Lookback active | Info `Skipping entries that are older than ... due to lookback` | Remove `--lookback`/`--quick`/`--fast` or the `--global-lookback`/`--lookback-global` scope |
| macOS without Full Disk Access | Startup Warning about Full Disk Access; protected folders unreadable | System Settings > Privacy & Security > Full Disk Access for the terminal app; run as root |
| Windows: only `C:` scanned | By default only the system drive (other partitions only when referenced) | v10 `--allhds`, v11 `--all-hard-drives`, or `-p D:\` |
| Not root/Administrator | Notice `THOR should be started 'As Administrator' ...` / `... as 'root' user ...` | Run elevated |
| Mounted image with a non-lab license | `Starting directory looks like a mounted disk image ...` | Still scanned; for full lab features see the `thor-scan` skill |

Filesystems skipped without `--alldrives` / `--all-drives`:

| | v10 | v11 |
|---|---|---|
| Linux | NFS, CIFS/SMB, AFS, Ceph, 9p, other network FS; pseudo FS (proc, sysfs, ...) always. Local USB/FUSE scanned | as v10 plus **every FUSE mount** (sshfs, ntfs-3g `fuseblk`, `target-mount`) treated as network |
| macOS | everything under `/Volumes/`, `~/Library/CloudStorage`, sshfs | sshfs and CloudStorage; `/Volumes` **is** scanned |
| Windows | UNC paths and mapped network drives; USB (removable) scanned | same |
| Auto | - | if the only `-p` path is on a network FS, `--all-drives` is switched on automatically (then needs a lab license) |

Workarounds for SSHFS/FUSE evidence on v11 without a lab license: copy the data locally or scan on the source
system. See the `thor-scan` skill for mounted-image and SSHFS recipes.

## 2. Output files missing or "empty"

| Situation | v10 | v11 |
|---|---|---|
| Default files | `<host>_thor_<time>.txt` (text log), `.html`, `<host>_files_md5s.csv` (no timestamp, overwritten each run) | `<host>_thor_<time>.jsonl` (JSON v3), `.html` (built from JSONL), CSV. **No text log unless `--text FILE`** |
| JSON | off; `--jsonfile=FILE` or bare `--jsonfile` (always use `=`: the optional value breaks when followed by another optional-value flag) | default; `--json FILE` sets the name, `--no-json` also removes the HTML report |
| Output directory | `-e`/`--rebase-dir` (only for names without a path separator) | `--output-directory` (alias `-e`, `--rebase-dir`), same rule |
| Placeholders | `:hostname:`, `:time:` | `<hostname>`, `<time>` (v10 tokens end up literally in names) |
| Default location | current working directory: `C:\Windows\System32` for scheduled tasks/GPO/SYSTEM | same |
| HTML missing | exit code != 0, `--nolog`, `--nohtml`, `--encrypt` | exit code != 0, `--no-html`, `--no-json` |

Rebuild an HTML report: `thor-util report --logfile <log>` (text or JSON/JSONL; encrypted logs must be
decrypted first). Convert formats: `thor-util logconvert` (`thor-maintenance` skill).

## 3. License errors at start (exit 1)

Read the reason without exposing the licensee: show only the redacted license lines.
```sh
# v11: lists all license candidates and exits
./thor-linux-64 --list-licenses --no-color 2>&1 | sed -E 's/[A-Z_]*OWNER: .* ([A-Z_]*TYPE: )/\1/'
# v10: read the Init lines of the last log the same way (--printlicenses prints all candidates during a scan)
grep -e 'License file found' -e 'No valid' -e "doesn't allow" HOST_thor_TIME.txt | sed -E 's/[A-Z_]*OWNER: .* ([A-Z_]*TYPE: )/\1/'
```
Licenses are encrypted files: never `grep`/`strings` a `.lic` to learn its type.

| REASON / message | Cause | Fix |
|---|---|---|
| hostname mismatch | Host-bound license for another host. Binding uses the short host name (`%COMPUTERNAME%`, `hostname`, `sysctl kern.hostname`), case-insensitive | License for this host; Management Center / Portal retrieval (`thor-deployment` skill) |
| expired / not yet valid | STARTS/EXPIRES outside today; wrong system clock | New license; fix clock |
| workstation license on a server | `client` (Workstation) type on Windows Server or Linux | Server & Workstation license |
| `The current license type doesn't allow ...` (lab mode, setting the hostname, virtual mapping, image scanning, drop zone, `--alldrives`, disabling the scan lock) | Lab-only feature with a standard license. Lab-class = Lab, Incident Response (Enterprise), Trial | Remove the flag (`--allhds`/`--all-hard-drives` instead of `--alldrives`) or use a lab license |
| License for the other edition (THOR Lite license with full THOR, or the reverse) | Edition mismatch | Use the binary that matches the license |
| `license requires challenge / response, which requires an interactive terminal` | Non-host-bound Lab/Trial license in a non-interactive run | Run interactively once per scan, or a host-bound license |
| `No valid license file found` only | No `*.lic` under the THOR folder (searched recursively) or `-q/--license-path`, and no `THOR_LICENSE` env var | Put the `.lic` in the THOR folder or `licenses/` subfolder |

Trial: Notice `Trial license detected, some output will be removed`. Silent license: no findings by design
(for update hosts and rollout tests). Lite: Notice about disabled modules plus a 5 s pause at start.

## 4. Other traps

- Binary names: Linux `thor-linux-64`, macOS `thor-macosx`, Windows `thor64.exe` (v10 32-bit `thor.exe` must
  not be used on 64-bit Windows), Lite `thor-lite-linux-64` / `thor-lite-macosx` / `thor64-lite.exe`. There is no `thor64` on Linux.
- Never put a value after a boolean flag (`--lab /mnt/x` fails); never mix v11 flag names into v10 command lines.
- v10 config migrated to v11 in place: `minmem: 50` = 50 bytes, `max_file_size: 31457280` keeps 30 MB,
  `cpulimit: 95` overrides the new default. Use `thor-util upgrade --reinitialize-config` (`thor-maintenance` skill).
- Old signatures: Warning `Signature file is older than 60 days` -> update (`thor-maintenance` skill).
- `THOR already running`: a second instance or stale lock; parallel scans need a lab license
  (v10 `--nodoublecheck`, v11 `--no-scan-lock`).
