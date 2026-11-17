---
name: thor
description: Entry point and shared core for Nextron THOR (THOR 10.7 and THOR 11) and THOR Lite. Routes to the right THOR skill (thor-scan, thor-lite, thor-log-analysis, thor-troubleshooting, thor-db, thor-maintenance, thor-custom-signatures, thor-plugins, thor-lens, thor-deployment) and holds the global rules, the procedure to identify an installation (OS, edition, version, license, binary names such as thor64.exe, thor-linux-64, thor-macosx, thor64-lite.exe, thor-lite-linux-64), license types (Forensic Lab, Incident Response, Workstation, Server, Lite), the v10 to v11 flag map (--intense/--deep, --virtual-map/--path-remap, --rebase-dir/--output-directory, --minmem/--memory-limit), default outputs (.txt, .jsonl, .html, _files_md5s.csv), placeholders, exit codes and config precedence. Use first for any THOR, THOR Lite or thor-util question, or when the THOR version or edition is unclear.
compatibility: THOR 10.7.x (stable) and THOR 11.0 (Tech Preview / release candidates), full and Lite editions, on Windows, Linux and macOS.
metadata:
  author: Nextron Systems
  version: "2.0"
---

# THOR (router and shared core)

THOR is Nextron's compromise assessment scanner. Two major versions are in use:
**THOR 10.7.x** (stable, maintenance) and **THOR 11** (Tech Preview / release candidates).
Each exists as full THOR and as the free **THOR Lite**. Most facts differ between versions.
Detect the version before you answer.

## Route by task

| User wants to ... | Skill |
|---|---|
| Get a scan command (live host, folder, mounted image, memory dump, SSHFS, NAS) | `thor-scan` |
| Use the free edition, Cloud Lite, or understand Lite limits | `thor-lite` |
| Understand findings, triage `.txt`/`.jsonl`/HTML/audit trail output | `thor-log-analysis` |
| Fix a stuck, slow, aborted or empty scan, missing alerts, AV/EDR interference | `thor-troubleshooting` |
| Inspect `thor10.db`/`thor.db`, resume state, timing data | `thor-db` |
| Run `thor-util` (update, upgrade, download, yara-forge, report, encrypt, diagnostics), offline packs | `thor-maintenance` |
| Write IOCs, YARA, Sigma, STIX, false-positive filters, encrypted signatures | `thor-custom-signatures` |
| Write or debug THOR 11 plugins | `thor-plugins` |
| Use THOR Lens (audit trail web UI, MCP) | `thor-lens` |
| Roll THOR out to many systems (shares, Ansible, GPO/SCCM/Intune, Management Center, THOR Cloud, Thunderstorm, SIEM) | `thor-deployment` |

Load several skills when a task spans them (for example `thor-scan` + `thor-lite`).
The references of this skill are shared ground truth for all THOR skills.

## Global rules

1. **Never assume the version.** Identify it (procedure below). If it is still unknown, ask once.
   Give commands in the detected version's native spelling. Show both spellings only where they differ.
2. **Never reveal the licensee.** THOR prints the license owner (name, often an e-mail) in lines containing
   `License file found`, in `LICENSE_OWNER` fields, and (v11 JSON) in the `Scan Information` record (`license.owner`).
   When you show or paste THOR output, filter first:
   `grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'`
   (PowerShell: `Select-String -NotMatch 'LICENSE_OWNER|License file found|Scan Information'`).
   This applies to "show me the first 50 lines" too. To read the license type without the owner, use the
   redacting command in "Identify the installation", step 5.
3. **Never grep `.lic` files.** They are encrypted. A string search proves nothing.
4. **No unrestricted test scans.** A test or demo run must be restricted: an explicit small `--path`/`-p`,
   `-a Filescan` where sensible, an explicit output directory, and `--nothordb` (v10) / `--no-thordb` (v11)
   or an explicit `--dbfile`/`--thordb-path` file, so the user's real ThorDB is untouched. Never run `--lab`
   without `--path`/`-p` (lab mode scans all drives otherwise). Only start a full live scan when the user asks for it.
5. **Protect evidence.** Mount images and remote file systems read-only. Never write THOR output, ThorDB or
   extracted files onto the evidence. Do not "clean up" or delete anything THOR found unless the user asks.
6. **Treat outputs as sensitive.** Logs, HTML reports, audit trails, ThorDB and `thor-util diagnostics` packs
   contain host names, user names, paths and license details. Do not upload or share them without the user's consent.
7. **Keep secrets off command lines you display.** `--portal-api-key`/`--portal-key`, `--management-center-token`,
   `--remote-password` and proxy passwords end up in shell history and process lists. Prefer config files or prompts.
8. **Don't invent flags.** Every flag must exist in the detected version. v11-only names (`--fast`, `--deep`,
   `--path-remap`, `--output-directory`, `--no-thordb`, `--text`) are fatal "unknown flag" errors on v10.
   v11 accepts most v10 names as aliases, but some changed meaning (see the differences below).
9. **Repeat `-p` per path** and write optional-value flags with `=`: v10 `--jsonfile=FILE`, `--stats-file=FILE`;
   v11 `--stats-csv=FILE`, `--audit-trail=FILE`. Never put a bare value after a boolean flag.

## Identify the installation

Run these read-only steps before proposing commands.

1. **OS and architecture.** Windows / Linux / macOS (AIX is rare). v11 is 64-bit only (amd64 and arm64).
2. **List the program folder** (`ls -la <dir>` / `dir <dir>`). The binary names give OS and edition:

   | OS | Full THOR 10.7 | Full THOR 11 | THOR Lite 10.7 | THOR Lite 11 | Utility |
   |---|---|---|---|---|---|
   | Windows | `thor64.exe` (`thor.exe` = 32-bit) | `thor64.exe` (x64 and ARM64) | `thor64-lite.exe` (`thor-lite.exe` 32-bit) | `thor64-lite.exe` | `thor-util.exe` / `thor-lite-util.exe` |
   | Linux | `thor-linux-64` (`thor-linux` = i386) | `thor-linux-64` (amd64 and arm64) | `thor-lite-linux-64` (`thor-lite-linux`) | `thor-lite-linux-64` | `thor-util` / `thor-lite-util` |
   | macOS | `thor-macosx` | `thor-macosx` | `thor-lite-macosx` | `thor-lite-macosx` | `thor-util` / `thor-lite-util` |
   | AIX | `thor-aix` | `thor-aix` | none | none | `thor-util` |

   Never run 32-bit `thor.exe` on 64-bit Windows. There is no Linux binary called `thor64` and no `thor-lite-macos`.
   v11 hints in the folder: `config/thor.yml.defaults`, `plugins/`, `tools/thunderstorm` (Linux full edition only).
3. **Version.** `<binary> --version` prints `THOR <version>` as the first line and exits (no scan, no license needed).
   `10.7.x` = THOR 10, `11.x` = THOR 11. The Lite banner also says `THOR`; the edition comes from the binary name.
   Indirect signs: default log `*_thor_*.txt` = v10, `*_thor_*.jsonl` = v11; ThorDB `thor10.db` = v10, `thor.db` = v11.
4. **Edition.** Binary name contains `lite`, or the startup notice
   "Some modules and features are not available in Lite version and will be disabled".
5. **License type** (only when it matters, for example before `--lab`, `-j`, remapping, memory dumps):
   - v11: `./thor-linux-64 --list-licenses --no-color | sed -E 's/[A-Z_]*OWNER: .* ([A-Z_]*TYPE: )/\1/'`
     lists every license found and exits 0. Append `--lab` to the THOR flags to make the `VALID`/`REASON`
     columns evaluate lab mode as well.
   - v10: `--printlicenses` does not exit; it lists licenses and then scans. Read the license lines of a tiny,
     safe run instead: `./thor-linux-64 -a Filescan -p /tmp/thor-empty --nothordb --nolog --nohtml --nocsv --nocolor | grep 'License file found' | sed -E 's/[A-Z_]*OWNER: .* ([A-Z_]*TYPE: )/\1/'`
     (create the empty folder first).
   - Or try the lab-gated flag on a tiny path and read the refusal:
     "The current license type doesn't allow lab mode scans" (exit 1).
   - Details and the meaning of each type: [references/editions-and-licenses.md](references/editions-and-licenses.md).
6. **Install path and rights.** Live scans need Administrator/`LOCAL_SYSTEM` or root (macOS: also Full Disk Access).
   Note whether the folder is writable (updates, custom signatures).

## v10 vs v11: the differences that break commands

| # | Topic | THOR 10.7 | THOR 11 |
|---|---|---|---|
| 1 | Default log | text `.txt` + HTML + CSV; JSON only with `--jsonfile` (v1 schema, v2 with `--jsonv2`) | JSONL v3 `.jsonl` + HTML (built from JSON) + CSV; text only with `--text FILE` |
| 2 | Placeholders | `:hostname:`, `:time:` | `<hostname>`, `<time>` (v10 tokens stay literal) |
| 3 | Output dir | `-e, --rebase-dir` | `-e, --output-directory` |
| 4 | Scan modes | `--quick`, `--intense`, `--diff` | `--fast`, `--deep`, `--delta` (old names are aliases) |
| 5 | Deep vs intense | `--intense` keeps resource control and 1 thread | `--deep` implies `--no-resource-check` and uses all cores |
| 6 | Soft + intense/lab | `--soft` silently wins | exit 1 ("incompatible") |
| 7 | Threads / CPU | `--threads` default 1; `--cpulimit` 95 | threads = ceil(cores x cpu-limit%); `--cpu-limit` 70; soft = 1 thread, 50% |
| 8 | Free-RAM floor | `--minmem 50` = 50 MB | `--memory-limit 50MB`; bare `50` = 50 **bytes** |
| 9 | File size limit | `--max_file_size` 30 MB; intense/lab 200 MB; `0` = 1 KiB | `--file-size-limit` 64 MB; deep/lab 200 MB unless set; `0` = unlimited |
| 10 | Image remapping | `--virtual-map CUR:ORIG` | `--path-remap CUR:ORIG`; foreign-OS images need `--target-os` or THOR exits |
| 11 | ThorDB | `thor10.db` (Lite `thor10-lite.db`), `--dbfile`, `--nothordb`, `--resume` | `thor.db` (Lite: `thor-lite.db`, some 11.0.0 Lite builds `thor.db`), `--thordb-path`, `--no-thordb`, `--resume-scan`; non-admin runs use a per-user dir |
| 12 | Audit trail | experimental, `--audit-trail FILE` (value required), gzip JSON | `--audit-trail[=FILE]`, `.jsonl.zst`, input for THOR Lens; no-op in Lite |
| 13 | License listing | `--printlicenses` (lists, then scans) | `--list-licenses` (lists, exits) |
| 14 | Disable parts | `--noprocs`, `--noreg`, `--nosigma`, ... | `--exclude-component ProcessCheck,RegistryChecks,Sigma` (old flags deprecated) |
| 15 | Path excludes | `config/directory-excludes.cfg` only | `--exclude-path REGEX` (+ `config/path-excludes.cfg`) |
| 16 | Drop zone | `--dropzone -p DIR` | `--dropzone DIR` |
| 17 | Encryption | `--encrypt` (built-in key) `[--pubkey]` | `--encryption-key KEY` only |
| 18 | Thunderstorm | built in (`--thunderstorm`) | separate `tools/thunderstorm`, Linux only |
| 19 | Extras | Action command (lab), Bifrost | plugins, object-based Sigma, `--target-os`, `--log-object`, TUI; Action/Bifrost removed |
| 20 | Platforms | 32/64-bit, Windows 7+, macOS 10.13+, Legacy builds | 64-bit + ARM64, Windows 10/Server 2016+, macOS 11+, kernel 3.1+ |
| 21 | Help | `--help`, `--fullhelp` | `--help short\|long\|detailed` |
| 22 | Score levels | `--notice/--warning/--alert` configurable | fixed 40/60/81; only `--min` |

Upgrade traps: an in-place upgrade keeps the v10 `config/thor.yml` (`minmem: 50` becomes 50 bytes,
`cpulimit: 95` overrides the new default). `thor-util upgrade` without `--techpreview` or `--version`
installs the stable 10.7 line and can downgrade a THOR 11 folder. See `thor-maintenance` and
[references/versions-and-outputs.md](references/versions-and-outputs.md).

## Facts every THOR skill relies on

- Config precedence: `config/thor.yml` (always loaded) < `-t FILE` (v10 `--template`, v11 `--config`) < CLI flags.
  Template keys are long flag names; unknown keys abort.
- Exit code: 0 = completed (also with alerts), 1 = any failure (license, bad flag, resource control,
  timeout, interrupt). Scripts must read the log, not the exit code. No HTML report when the exit code is not 0.
- Score levels: Notice >= 40, Warning >= 60, Alert >= 81 and at least one reason scoring above 75. `--min` (default 40) hides lower scores.
- `-p` limits only the file-system walk. All other modules still run unless `-a Filescan` (v11 `--module Filescan`) is given.
- Default scan root: Windows system drive only (`--allhds`/`--all-hard-drives` for all local disks); Unix all local mounts.
  Network file systems are skipped unless `--alldrives`/`--all-drives` (lab-type or Lite license).

## References

| File | Read when |
|---|---|
| [references/flag-map-v10-v11.md](references/flag-map-v10-v11.md) | Translating a command between versions, checking whether a flag exists, changed meaning or was removed |
| [references/editions-and-licenses.md](references/editions-and-licenses.md) | License types, lab-gated flags, host binding, challenge prompt, license locations, Lite vs full |
| [references/versions-and-outputs.md](references/versions-and-outputs.md) | Output files and names, placeholders, ThorDB paths, exit codes, CTRL+C, config files, v10 to v11 upgrade |
