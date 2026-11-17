# ThorDB locations

## Defaults

| OS / context | v10 (10.7.x) | v11 |
|---|---|---|
| Windows, elevated | `%ProgramData%\thor\thor10.db` | `%ProgramData%\thor\thor.db` |
| Windows, not elevated | same path (no per-user fallback) | `%LOCALAPPDATA%\thor\thor.db` |
| Linux, root | `/var/lib/thor/thor10.db` | `/var/lib/thor/thor.db` |
| Linux, non-root | same path; normally not writable -> Error, scan continues without ThorDB | `$XDG_STATE_HOME/thor/thor.db`, default `~/.local/state/thor/thor.db` |
| macOS, root | `/var/lib/thor/thor10.db` | `/var/lib/thor/thor.db` |
| macOS, non-root | same path (see Linux) | `~/Library/Application Support/thor/thor.db` |
| AIX | `/var/lib/thor/thor10.db` | `/var/lib/thor/thor.db` |
| THOR Lite | `thor10-lite.db` in the same folders | intended `thor-lite.db`; some 11.0.0 Lite builds still use `thor.db` |

v11 decides "admin" at start: Unix effective UID 0; Windows: process can open the first physical drive
(i.e. elevated). Early THOR 11 Tech Preview builds still used `thor10.db`; the v11 manual mentions
`thor10.db` in places, which is outdated.

The folder is created with mode 0700 (root-only on Unix). Reading it needs the same rights THOR had.

## Custom location

| | v10 | v11 |
|---|---|---|
| Flag | `--dbfile <file>` | `--thordb-path <file>` (alias `--dbfile`) |
| Template key | `dbfile:` | `thordb-path:` (or `dbfile:`) |
| Value | file path; environment variables and `:hostname:`/`:time:` are expanded | file path |

Always a file name, never a directory: `--thordb-path /var/lib/thor/fileserver-scan.db`. A directory makes
the open fail and THOR runs without ThorDB. A separate DB per scan job keeps resume states apart (the context
key already separates different argument sets inside one DB).

## Which DB did a given run use?

Read the Init lines of that run's log (filter license lines as usual):
```sh
grep -e 'ThorDB' HOST_thor_TIME.txt                                       # v10 text log
grep 'ThorDB' HOST_thor_TIME.jsonl | jq -r '[.meta.level,.message,(.fields|tostring)]|@tsv'   # v11
```
`Successfully opened ThorDB` / `Successfully created ThorDB` show the path; `Could not ...` /
`ThorDB database is not writable` mean the run had no ThorDB. No ThorDB line at all: ThorDB was disabled
(`--nothordb`, `--no-thordb`, `--exclude-component ThorDB`, lab/dropzone mode).

Find files on disk:
```sh
sudo ls -l /var/lib/thor/ ~/.local/state/thor/ "$HOME/Library/Application Support/thor/" 2>/dev/null
```
```powershell
Get-ChildItem "$env:ProgramData\thor", "$env:LOCALAPPDATA\thor" -Filter 'thor*.db' -ErrorAction SilentlyContinue
```

## Size and deletion

The DB is small (key/value entries plus at most a few hundred timing rows). Deleting it is never needed for
performance. It removes: resume state, per-module last-run times (delta scans start over with full scans),
and the baselines for "new entry" detections (Autoruns, services, hosts file, authorized_keys, ShimCache).
If a fresh state is wanted, the user should move the file aside rather than delete it, while no THOR runs.

`thor-util diagnostics` copies the DB from the **default** path only (as `thordb.db`), ignoring custom paths.
