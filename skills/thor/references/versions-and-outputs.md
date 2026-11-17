# THOR versions: outputs, ThorDB, exit codes, signals, configuration, upgrade

## Default output files

Output goes to the **current working directory** unless `-e` is given (v10 `--rebase-dir`, v11 `--output-directory`).
A scheduled task or GPO job runs in `C:\Windows\System32`, so always set `-e`.
Only file names **without a path separator** are moved into the `-e` directory; names with a separator are used as given.

| Output | THOR 10.7 | THOR 11 |
|---|---|---|
| Text log | **on**: `:hostname:_thor_:time:.txt` (`-l/--logfile`, off with `--nolog`) | **off**; `-l/--text FILE` enables it (format reconstructed from objects, close to v10) |
| JSON log | off; `--jsonfile[=FILE]` -> `:hostname:_thor_:time:.json`, schema v1 (v2 with `--jsonv2`) | **on**: `<hostname>_thor_<time>.jsonl`, JSON v3 (one object per line); `--json FILE` renames, `--no-json` disables (and kills HTML) |
| HTML report | on, end of scan, built from the text log: `:hostname:_thor_:time:.html` | on, end of scan, built from the JSON log: `<hostname>_thor_<time>.html` |
| CSV (`md5,path,score`, Filescan findings) | on: `:hostname:_files_md5s.csv` (no time stamp, overwritten every run) | on: `<hostname>_files_md5s.csv` |
| Stats CSV (one summary line) | `--stats-file=FILE` (bare: `:hostname:_stats.csv`) | `--stats-csv=FILE` (bare: `<hostname>_stats.csv`) |
| Audit trail (every assessed element) | `--audit-trail FILE` (value required; gzip JSON; experimental; not moved by `-e`, no placeholders: give an absolute path) | `--audit-trail[=FILE]` (bare: `<hostname>_thor_audit_<time>.jsonl.zst`, zstd JSONL); no-op in Lite |
| Collector ZIP | `:hostname:_collector.zip` | `<hostname>_collector.zip` |

When outputs are skipped:

- **No HTML report** when THOR exits non-zero (interrupt, timeout, resource control, license error) in both versions.
  Regenerate later with `thor-util report` (see `thor-maintenance`).
- v10: `--nolog` also removes the HTML report; `--encrypt` disables HTML.
- v11: `--no-json` also removes the HTML report; encryption (`--encryption-key`) disables HTML.
- Drop zone and Thunderstorm modes write no HTML and no CSV.
- Text, JSON and syslog are written in real time; HTML and CSV at the end.

Other sinks: syslog `-s host[:port[:DEFAULT|CEF|JSON|SYSLOGJSON|SYSLOGKV[:UDP|TCP|TCPTLS]]]` (default `:514:DEFAULT:UDP`;
v11 also `https://url[:JSON]`), `--local-syslog` (facility local0), `--eventlog` (Windows Application log).

## Placeholders

| | THOR 10.7 | THOR 11 |
|---|---|---|
| Hostname | `:hostname:` | `<hostname>` |
| Scan start time | `:time:` (`2006-01-02_1504`, local; UTC with `--utc`) | `<time>` (`YYYY-MM-DD_HHMM`, local; UTC with `--timestamp-utc`) |
| Env vars | `%COMPUTERNAME%`, `$HOME` expanded in path and file flags | same |

v11 does not expand `:hostname:`; v10 does not expand `<hostname>`. Wrong tokens end up literally in file names.
In shells, quote `<...>` (it is a redirection otherwise): `--json "<hostname>_scan.jsonl"`.

Environment expansion gotcha: v10 expands variables in `-p` values, so `C:\$Recycle.Bin` loses `$Recycle`
(becomes `C:\.Bin`). On Unix the shell expands `$...` first unless you single-quote. Workarounds: scan the parent folder,
or set `Recycle='$Recycle'` in THOR's environment. Current v11 builds skip expansion when the literal path exists.

## Scan ID, timestamps, personal data

- Every line carries a scan ID (`S-` + 11 random characters). Set one with `-i ID` (v10 `--scanid`, v11 `--scan-id`)
  to group several runs (for example several partitions of one image).
- `--utc` (v10) / `--timestamp-utc` (v11) for multi-timezone collections; JSON timestamps are always RFC 3339.
- `--suppresspi`/`--brd` (v10) / `--no-personal-data` (v11) replaces user names with `ANONYMIZED_BY_THOR` (best effort).

## ThorDB

| | THOR 10.7 | THOR 11 |
|---|---|---|
| File name | `thor10.db` (Lite `thor10-lite.db`) | `thor.db` (Lite intended `thor-lite.db`; some 11.0.0 Lite builds still use `thor.db`); early v11 Tech Previews still used `thor10.db`; there is no `thor11.db` |
| Admin/root location | `%ProgramData%\thor\` / `/var/lib/thor/` | same |
| Non-admin location | same as admin | `%LOCALAPPDATA%\thor\`, `~/.local/state/thor/` (Linux), `~/Library/Application Support/thor/` (macOS) |
| Custom location | `--dbfile FILE` | `--thordb-path FILE` (must be a file, not a directory) |
| Disable | `--nothordb` | `--no-thordb` (= `--exclude-component ThorDB`) |
| Forced off by | `--lab`, `--dropzone`, `--thunderstorm` | `--lab`, `--dropzone`, Thunderstorm |
| Resume | `--resume` on **every** run incl. the first; same scan flags (order doesn't matter; output, log and ThorDB-path flags ignored) | `--resume-scan` on every run incl. the first; same flags (order and alias spelling don't matter) |

Resume restores only the Filescan position, which is stored infrequently, so a resumed scan rescans or skips some
elements by design. A run without the resume flag discards the saved state. `--diff`/`--delta` needs a previous
completed scan in the DB. Details: `thor-db` skill.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed, **regardless of findings** (alerts do not change the code). v10.7 also exits 0 when the `-p` path does not exist (nothing scanned). In v10 a drop zone/Thunderstorm run stopped by license expiry also exits 0 |
| 1 | Any failure: invalid/missing license or refused lab feature, unknown flag or positional argument, unknown module, another THOR instance running (scan lock), `--require-admin`/`--require-elevation` without admin, insufficient RAM, resource control stop, timeout (`--max_runtime`/`--timeout`), interrupt (CTRL+C, SIGTERM, SIGHUP), YARA crash; v11 also: exit from the TUI, stop via command pipe, `--thunderstorm` |

Automation must check the log (and `--stats-csv`/`--stats-file` counters), not only the exit code.

## CTRL+C and signals

| | THOR 10.7 | THOR 11 |
|---|---|---|
| CTRL+C in an interactive console | Menu shows the current elements: `C` continue, `E` exit, `X` cancel the current module | TUI menu: `C` continue, `Q`/`E` exit; a **second CTRL+C while the menu is open exits immediately** |
| SIGINT without a console (service, script, `kill -INT`) | exits 1, no HTML report | exits 1 |
| SIGTERM / SIGHUP | exits 1 | exits 1 |

To see what a running scan is doing, prefer `thor-util diagnostics` (see `thor-troubleshooting`) over sending signals.
Windows consoles with QuickEdit mode pause THOR when text is selected; press Enter to resume.

## Resource stops

- Free RAM below the floor (v10 `--minmem` 50 MB, v11 `--memory-limit` 50MB) -> scan stops, exit 1.
- Log flood guard: v10 switches to reduced logging (Notice and above) after 60 MB of log and exits after 64 MB;
  v11 `--log-size-limit` (default 200MB) switches 4 MB before the limit and cancels when exceeded.
  Disabled by `--norescontrol`/`--no-resource-check`, `--debug`, `--trace`, `--printall`/`--print-files`, and the modes that imply resource control off (v10 lab/drop zone; v11 deep/lab/drop zone).
- Runtime limit: 168 h by default (v10 `--max_runtime`, v11 `--timeout`; 0 = none), message
  "Maximum runtime has exceeded/has been exceeded, killing THOR" with the elements in progress.
- Low disk space only produces a warning.

## Configuration files and precedence

1. `<thor>/config/thor.yml` is always loaded.
2. `-t FILE` (v10 `--template`, v11 `--config`) overrides it. Only one extra file.
3. Command-line flags override both.

Template keys are long flag names (`remote-log`, not `-s`); unknown keys abort the start. `--generate-config` (v10) /
`--config-preview` (v11) prints the YAML for a command line. The v10 manual says thor.yml "always takes precedence";
the code applies the order above.

Shipped `config/thor.yml`:

| v10 | v11 |
|---|---|
| `max_file_size: 31457280`, `max_file_size_intense: 209715200`, `max_runtime: 168`, `cpulimit: 95`, `minmem: 50`, `min: 40`, `truncate: 2048` | every line commented (built-in defaults apply); full reference in `config/thor.yml.defaults` |

Other files in `config/`: `false_positive_filters.cfg` (regex on the full log line), `directory-excludes.cfg`
(v10; v11 reads `path-excludes.cfg` and still the old name), optional `registry-excludes.cfg`, `eventlog-excludes.cfg`,
`process-excludes.cfg` (both versions), and when present `sigma.yml` and `thor-util.yml` (thor-util settings).

## Upgrading v10 -> v11 (what breaks)

1. **Config migration.** An in-place `thor-util upgrade --techpreview` keeps the old `config/thor.yml`. In v11 that means
   `minmem: 50` = 50 bytes (free-RAM guard effectively off), `cpulimit: 95` overrides the new 70 default, and
   `max_file_size: 31457280` keeps the 30 MB limit. Fix: back up, then `thor-util upgrade --reinitialize-config --techpreview`
   (resets thor.yml, not a conversion), and re-add settings with v11 names and units (`memory-limit: 50MB`,
   `file-size-limit: 64MB`). If you used the v10 defaults, delete `max_file_size` and `max_file_size_intense`.
   v11 warns at start about suspicious values ("... is set to N, which is unreasonably small").
2. **Scripts and templates.** Old flag names mostly still parse but some changed meaning (`--minmem`, `--dropzone`,
   `--jsonfile`, `-l`). Unknown in v11: `--encrypt`, `--printlicenses`, `--nocolor`, `--showall`, Thunderstorm
   server flags, Bifrost. Use `--help detailed` to review.
3. **Log consumers.** Default log is now `.jsonl` (v3 schema, https://github.com/NextronSystems/jsonlog). Update
   collectors and SIEM parsers; add `--text FILE` only where a text log is still required.
4. **Custom signatures.** v11 requires the subfolders `custom-signatures/iocs/`, `yara/`, `sigma/`, `stix/`;
   `thor-util upgrade` moves loose files. YARA Forge moves from `custom-signatures/yara-forge/` (v10) to
   `custom-signatures/yara/yara-forge/` (stored encrypted in both versions). Details: `thor-custom-signatures`, `thor-maintenance`.
5. **Resources.** v11 needs about 40% more RAM; threads now follow `--cpu-limit` (more cores used by default).
6. **Platforms.** No 32-bit builds; Windows 10/Server 2016+, macOS 11+, Linux kernel 3.1+.
7. **Staying on v10 / going back.** Plain `thor-util upgrade` (no `--techpreview`, no `--version`) installs the stable
   10.7 line, which downgrades a THOR 11 folder. Pin with `thor-util upgrade --version ^10.0.0` or keep v11 in a
   separate folder (recommended).
8. **ThorDB.** New file name `thor.db`; v11 does not read `thor10.db`, so resume and delta state start fresh.
