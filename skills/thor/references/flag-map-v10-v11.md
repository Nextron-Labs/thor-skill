# THOR flag map: v10 (10.7.x) -> v11

Verified against THOR 10.7 and THOR 11 builds. Rules for reading the tables:

- **Alias** = v11 still accepts the v10 spelling (on the CLI and as a YAML key), often hidden from `--help`.
  An accepted alias does **not** guarantee the same meaning: check the "Same name, different meaning" section.
- **Deprecated** = v11 prints "Flag --x has been deprecated" on stderr; the note says whether it still has an effect.
- **Unknown** = v11 aborts with a usage error and exit 1.
- v10 never accepts v11-only names. A v11 command line run on 10.7 fails on the first new name.
- Short flags are unchanged unless noted: `-p -a -e -l -o -j -m -r -s -x -i -c -f -n -q -t`.

## 1. Placeholders and value syntax

| Item | v10 | v11 |
|---|---|---|
| Host / time placeholder | `:hostname:`, `:time:` | `<hostname>`, `<time>` (`YYYY-MM-DD_HHMM`, local; UTC with `--timestamp-utc`) |
| Where expanded | `-j`, `-p`, log/json/html/csv names, `--rebase-dir`, `--scanid`, `--dbfile`, `--stats-file`, syslog, license path, collector output (not `--audit-trail`) | all string flags and template values incl. `--audit-trail` |
| Environment variables | expanded in the same values (`%COMPUTERNAME%`, `$HOME`) | same; a `--path` value that exists literally is not expanded |
| Sizes | `--max_file_size` etc. accept `KB/MB/GB/TB` (1024-based); `--minmem` is plain MB | every size flag: bare number = **bytes**, or `KB/MB/GB/TB` |
| Multiple values | repeat the flag (`-p A -p B`) | repeat the flag, or one CSV record per occurrence (`--path A,B`); quote values containing commas (`"\"a{1,3}\""`) |
| Positional arguments | rejected: "Positional arguments specified, but THOR only uses flags" (exit 1) | same |

### The `=` quirk (both versions)

Optional-value flags only take a value in `--flag=value` form. With a space, the value becomes a positional
argument and THOR exits 1. A pre-parse repair catches some cases but skips the argument after each repair,
so `--jsonfile a.json --stats-file s.csv` and `--jsonfile a.json --path /a /b` fail, and the repair never works for `-p A B`.

| Version | Optional-value flags (always write `=`) |
|---|---|
| v10 | `--jsonfile[=FILE]` (bare = `:hostname:_thor_:time:.json`), `--stats-file[=FILE]` (bare = `:hostname:_stats.csv`) |
| v11 | `--stats-csv[=FILE]` / alias `--stats-file` (bare = `<hostname>_stats.csv`), `--audit-trail[=FILE]` (bare = `<hostname>_thor_audit_<time>.jsonl.zst`) |

Also: never put a value after a boolean flag (`--lab /mnt/x` is read as `--lab=/mnt/x` and fails), and repeat `-p` per path.
v10 `--audit-trail` requires a value; v11 `--json` requires a value.

## 2. Configuration, help, information

| v10 | v11 | Status | Notes |
|---|---|---|---|
| `-t, --template FILE` | `-t, --config FILE` | alias | thor.yml < template < CLI in both |
| `--generate-config` | `--config-preview` | alias | prints YAML for the given flags |
| `-h, --help` | `-h, --help [short\|long\|detailed]` | same | |
| `--fullhelp` | `--help detailed` (`--fullhelp` hidden alias) | alias | |
| `--version` | `--version` | same | prints `THOR <version>`, exits |
| `--print-signatures`, `--print-signatures-json` | `--list-signatures`, `--list-signatures-json` | alias | list and exit |
| `--printlicenses` | `--list-licenses` | **unknown** in v11 | v10 prints all licenses and still scans; v11 lists and exits |
| `--printall` | `--print-files` | alias | every checked file (huge) |
| (none) | `--list-deepscan-criteria` (alias `--print-deepscan-criteria`) | v11 only | |
| `--completions SHELL` | same | same | |
| `--debug`, `--trace` | same | same | |

## 3. Targets and paths

| v10 | v11 | Status | Notes |
|---|---|---|---|
| `-p, --path DIR[:NOWALK]` | same | same | `:NOWALK` = no recursion. Default: Windows system drive, Unix `/` |
| `--allhds` | `--all-hard-drives` | alias | Windows only |
| `--alldrives` | `--all-drives` | hidden alias | network drives too; lab-type or Lite license (or special). v11 enables it automatically when the single `--path` is on a network FS |
| `--follow-symlinks` | same | same | |
| `--cross-platform` | `--cross-platform-paths` | alias | filename IOCs match `\` and `/` paths |
| `--require-admin` | `--require-elevation` | alias | |
| `--wsl` (10.7.30+) | same | same | Windows: walk WSL distributions |
| (none) | `--target-os Windows\|Linux\|MacOS\|AIX` | v11 only | path style, heuristics, built-in excludes of the scanned OS |

## 4. Scan modes and timeframe

| v10 | v11 | Status | Notes |
|---|---|---|---|
| `--quick` | `--fast` | alias | 3-day Filescan lookback; drops Eventlog, EVTX, LogScan, Firewall, Profiles, Hotfixes, MFT |
| `--soft` | `--soft` | same name | see section 11 |
| `--nosoft` | `--no-soft` | hidden alias | |
| `--intense` | `--deep` | alias | see section 11 |
| `--diff` | `--delta` | alias | needs ThorDB; v11: fatal together with `--lookback` |
| `--lab` (alias `--fsonly`) | `--lab` | same | lab-type license |
| `--lookback N` | same | same | v10 default module list: Eventlog (Windows), **empty** on Linux/macOS; v11: Eventlog |
| `--global-lookback` | `--lookback-global` | alias | |
| `--lookback-modules` | `--lookback-module` | alias | |
| `--force-aptdir-lookback` | `--lookback-aptdirs` | alias | |
| `-f, --epoch` | `-f, --highlight-timeframe` | alias | |
| `--epochscore` | `--highlight-timeframe-score` | alias | default 35 |
| `--pure-yara` | same | same | |
| `--allfiles` | `--files-all` | alias | all files deep-scanned; size limit 200 MB unless set |

## 5. Forensic lab, images, memory dumps, drop zone, collector

| v10 | v11 | Status | Notes |
|---|---|---|---|
| `--virtual-map CUR:ORIG` | `--path-remap CUR:ORIG` | alias | lab-type license or special |
| `-j, --overwrite-hostname` | same | same | lab-type license or special |
| `--nodoublecheck` | `--no-scan-lock` | alias | lab-type license or special |
| `-m, --image_file` | `-m, --memory-dump-file` | alias | single dump, DeepDive |
| `--image-chunk-size` | `--memory-dump-chunk-size` | alias | default 12 MB |
| `-r, --restore_directory` | `-r, --memory-dump-extraction-directory` | alias | |
| `--restore_score` | `--memory-dump-extraction-score` | alias | default 50 |
| `--dumpscan` | `--memory-dumps` | alias | dumps found during Filescan; on in intense/deep |
| `--dropzone` (bool, dir via `-p`) | `--dropzone DIR` | **changed** | see section 11 |
| `--dropdelete` | `--dropzone-purge` | alias | deletes scanned files |
| `--dropzone-delay` | same | same | |
| `--collector`, `--collector-only`, `--collector-config`, `--collector-no-mft` | same | same | Incident Response license or `deepforensic` special |
| `--collector-output` | same | same | ZIP file path; placeholder syntax changed |
| `--collector-print-config` | `--collector-config-preview` | alias | |
| `--collector-dry-run` | `--collector-preview` | alias | |
| `--collector-max-filesize` | `--collector-file-size-limit` | alias | |

## 6. Resources and limits

| v10 | v11 | Status | Notes |
|---|---|---|---|
| `-c, --cpulimit` | `-c, --cpu-limit` | alias | default 95 -> 70; v11 also derives the thread count |
| `--nocpulimit` | `--no-cpu-limit` | deprecated, still works | v11: use `--cpu-limit 100` |
| `--norescontrol` | `--no-resource-check` (also `--no-rescontrol`) | hidden alias | |
| `--minmem MB` | `--memory-limit SIZE` | alias, **changed** | bare number = bytes in v11 |
| `--threads` | same | same | v10 default 1; v11 derived |
| `--lowprio`, `--verylowprio`, `--lowioprio`, `--nolowprio` | `--low-priority`, `--very-low-priority`, `--low-io-priority`, `--no-low-priority` | alias | |
| `--max_file_size` | `--file-size-limit` | alias | 30 MB -> 64 MB; `0`: 1 KiB (v10) vs unlimited (v11) |
| `--max_file_size_intense` | same | deprecated, still honoured | v11: deep limit = max of both if both set |
| `--force-max-file-size` | `--enforce-file-size-limit` | alias | apply the limit to hives, logs, EVTX too |
| `--max_process_size` | `--process-size-limit` | alias | 2 GB; soft 500 MB |
| `--max_log_lines` | `--log-line-limit` | alias | 1,000,000 |
| `--max_runtime` | `--timeout` | alias | hours, default 168, 0 = none |
| `--max-recursion-depth` | `--archive-depth` | alias | 4 |
| `--max-nested-objects` | `--archive-file-limit` | alias | 10,000 -> 100,000; 0 in deep |
| `--bulk-size` | `--chunk-size` | alias | 20 MB (intense/deep 100 MB, soft 1 MB) |
| `--yara-timeout`, `--yara-stack-size` | same | same | |
| `--buffer_size`, `--nolockthread` | same / `--no-thread-lock` | deprecated, no effect | |
| (hard-coded 60/64 MB log flood guard) | `--log-size-limit` (alias `--max-log-size`), 200 MB | v11 only | |

## 7. Modules and features

| v10 | v11 | Status | Notes |
|---|---|---|---|
| `-a, --module M` | same | same | v11 names are case-insensitive |
| `--noprocs --nofilesystem --noreg --nousers --nologons --noautoruns --noeventlog --norootkits --noevents --nodnscache --noenv --nohosts --nomutex --notasks --noservices --noprofiles --noatjobs --nonetworksessions --nonetworkshares --noshimcache --nohotfixes --nowmistartup --nofirewall --nowmi --nolsasessions --nomft --nopipes --noetwwatcher --nointegritycheck --notimestomp --nocron` | `--exclude-component NAME[,NAME]` (alias `--disable-module`) | deprecated, still work | e.g. `--exclude-component ProcessCheck,Mutex,Pipes` |
| `--nologscan`, `--noevtx`, `--noregistryhive` | `--exclude-component LogScan` / `Eventlog` / `RegistryChecks` | deprecated, still work | |
| `--nothordb` | `--no-thordb` | hidden alias | = `--exclude-component ThorDB` |
| `--nosigma --noyara --noarchive --noc2 --noprochandles --noprocconnections --noamcache --noexedecompress --nowebdirscan --novulnerabilitycheck --noprefetch --nogroupsxml --nowmipersistence --nolnk --noknowledgedb --nower --noauthorizedkeys --noeml --noetl --noauditlog --nomftfile --nounescape --noimphash --nommap` | `--no-sigma --no-yara --no-archive ...` (dash form) | hidden alias | prefer `--exclude-component` in v11 |
| `--nostix` | `--no-stix-iocs` | alias | |
| `--mft` | `--mft-analysis` | alias | Windows; on by default only in intense/deep |
| `--ads` | `--alternate-data-streams` | alias | |
| `--full-registry` | `--no-builtin-registry-excludes` | alias | |
| `--noregwalk` | `--essential-live-registry-only` | hidden alias | |
| `--showdeleted` | `--log-deleted-files` | alias | |
| `--process` | `--process-id` | alias | |
| `--dump-procs`, `--max-procdumps`, `--procdump-dir` | `--process-dump`, `--process-dump-limit`, `--process-dump-directory` | alias | v11 Windows only |
| `--processintegrity`, `--full-proc-integrity` | `--process-integrity`, `--process-integrity-full` | alias | Windows |
| `--c2-in-memory`, `--custom-c2-in-memory` | `--c2-memory-analysis`, `--custom-c2-memory-analysis` | alias | |
| `--nodoublepulsar` | `--no-doublepulsar` | hidden alias | |
| `-n, --eventlog-target` | same | same | |
| `--sigma`, `--timestomp`, `--split-registry-keys` | same | deprecated, no effect | |

## 8. Signatures

| v10 | v11 | Status | Notes |
|---|---|---|---|
| `--customonly` | `--custom-signatures-only` | alias | |
| `--init-selector` | `--signature-include` | alias | substring over name, tags, description |
| `--init-filter` | `--signature-exclude` | alias | same matching: broad words drop many rules |
| `--minimum-sigma-level` | `--sigma-threshold` | alias | informational, low, medium, high (default), critical; deep/intense -> medium |
| (none) | `--sigma-ruleset core\|core+\|core++\|emerging_threats\|threat_hunting\|all` | v11 only | overrides the threshold logic |
| `--string-context` | `--match-context` | alias | |

## 9. Output files and formats

| v10 | v11 | Status | Notes |
|---|---|---|---|
| `-e, --rebase-dir` | `-e, --output-directory` | alias | only names without a path separator are moved there |
| `-l, --logfile` | `-l, --text` | hidden alias, **changed** | v10 text log on by default; v11 only when given |
| `--nolog` | `--no-log` | deprecated | v11 text log is off anyway |
| `--htmlfile`, `--nohtml` | `--html`, `--no-html` | alias | v10 HTML from text log; v11 from JSON |
| `--jsonfile[=F]` | `--json F` | alias, **changed** | v11 requires a value and writes JSON by default |
| `--json` (hidden bool) | `--json F` | **changed** | |
| `--jsonv2` | same | deprecated, no effect | v11 always writes JSON v3 |
| (none) | `--no-json` | v11 only | also disables the HTML report |
| `-o, --csvfile`, `--nocsv` | `-o, --csv`, `--no-csv` | alias | CSV on by default in both |
| `--stats-file[=F]` | `--stats-csv[=F]` | alias | use `=` |
| `--csvstats` | `--csv-stats` | deprecated | |
| `--audit-trail F` | `--audit-trail[=F]` | **changed** | gzip JSON vs `.jsonl.zst` |
| `--appendlog`, `--keyval` | `--log-append`, `--key-value` | alias | |
| `--encrypt` | (none) | **unknown** | v11 encrypts when `--encryption-key` is given |
| `--pubkey` | `--encryption-key` | alias | RSA public key (PEM file or inline) |
| `--include-info-in-html` | `--html-include-info` | alias | |

## 10. Console, levels, reporting

| v10 | v11 | Status | Notes |
|---|---|---|---|
| `-x, --min` | same | same | default 40 |
| `--notice`, `--warning`, `--alert` | `--score-notice` ... | deprecated, no effect | v11 thresholds fixed |
| `--max-reasons` | `--alert-reason-limit` | alias | 2; 0 = all |
| `--allreasons` | same | deprecated, works | = `--alert-reason-limit 0` |
| `--max-hits` | `--match-limit` | alias | 10,000 -> 100,000; 0 in lab |
| `--showall` | (none; hidden deprecated `--show-all`) | **unknown** spelling | v10 `--showall` lifts the per-rule output cap and the Sigma muting ("Sigma rule triggered more than 10 times"). v11: `--match-limit 0` lifts the hit cap; the muting (live Eventlog module only) is lifted by `--lab` or `--show-all`, not by `--match-limit 0` |
| `-i, --scanid`, `--scanid-prefix`, `--noscanid` | `-i, --scan-id`, `--scan-id-prefix`, `--no-scan-id` | hidden alias | |
| `--utc`, `--rfc3339` | `--timestamp-utc`, `--timestamp-rfc3339` | alias | |
| `--cmdjson`, `--cmdkeyval` | `--console-json`, `--console-key-value` | alias | |
| `--genid` | `--log-message-ids` | alias | |
| `--suppresspi` (`--brd`) | `--no-personal-data` | alias | |
| `--nocolor` | `--no-color` | **unknown** in v11 | |
| `--background` | `--console-background` | alias | |
| `--registry_depth_print` | `--print-registry-depth` | alias | |
| `--printshim`, `--printamcache` | `--log-object "SHIM cache entry"` / `"Amcache entry"` | deprecated, works | |
| `--nofserrors` | `--no-fs-errors` | hidden alias | |
| `--silent`, `--reduced`, `--ascii`, `--truncate`, `--eventlog`, `--local-syslog` | same | same | |

## 11. Same name (or alias), different meaning

| Flag | v10 | v11 |
|---|---|---|
| `--minmem` / `--memory-limit` | integer MB | bytes unless a unit is given: `--minmem 50` = 50 bytes, effectively off |
| `--max_file_size` / `--file-size-limit` `0` | 1 KiB (almost no content scanned) | unlimited |
| explicit `--max_file_size` with intense/lab/allfiles | the 200 MB bump happens only while the limit equals the 30 MB default; a different value is used as is (verify with the startup line "Max. file size to be scanned is ...") | explicit value also applies to `--deep`/`--lab` |
| `--intense` / `--deep` | resource control and CPU limit stay on, 1 thread | implies `--no-resource-check`, all cores, no log-size limit |
| `--soft` | caps CPU at 70%, silently overrides `--intense`/`--lab` | CPU 50%, 1 thread; exit 1 with `--deep`, `--lab`, `--dropzone`, `--no-resource-check` |
| `--dropzone` | boolean, directory via `-p` | takes the directory: `--dropzone DIR` (v10 syntax breaks) |
| `--jsonfile` | optional value, JSON off by default | alias of `--json`, value required, JSON on by default |
| `-l/--logfile` | rename the default text log | enables the text log (`--text`) |
| `--cpulimit` | 95, pause only | 70, also sets thread count |
| `--threads` default | 1 (all cores in lab/dropzone/thunderstorm) | ceil(cores x cpu-limit%); 1 in soft |
| `--lab` | Filescan only, `-a` ignored | Filescan only, `-a` can only narrow; references followed only via `--path-remap` |
| `--resume` / `--resume-scan` | state key = hash of the set scan flags (order doesn't matter; output, log, debug and ThorDB-path flags ignored) | canonicalised flag list (order and aliases don't matter) |
| `--audit-trail` | value required, gzip JSON, not rebased/expanded | optional value, zstd JSONL v3, placeholders expanded |
| `--lookback` alone on Linux/macOS | does nothing (empty module list) | applies to Eventlog only (Windows module) |

## 12. ThorDB, remote logging, license retrieval, THOR Remote, VirusTotal

| v10 | v11 | Status |
|---|---|---|
| `--dbfile FILE` | `--thordb-path FILE` | alias (value must be a file) |
| `--resume`, `--resumeonly` | `--resume-scan`, `--resume-only` | alias / hidden alias |
| `-s, --syslog` | `-s, --remote-log` | alias (`host[:port[:fmt[:proto]]]`; v11 also `https://url[:JSON]`) |
| `--rfc3164` (`--rfc3162`), `--rfc5424`, `--rfc` | `--syslog-rfc3164`, `--syslog-rfc5424`, `--syslog-strict` | alias |
| `--maxsysloglength`, `--cef_level` | `--syslog-length-limit`, `--syslog-cef-level` | alias |
| `-q, --license-path` | same | same |
| `--management-center`, `--management-center-token` (`--asgard`, `--asgard-token`) | same | same (`--management-center-host` does not exist) |
| `--portal-key`, `--portal-nonewlic`, `--portal-contracts` | `--portal-api-key`, `--portal-existing-license`, `--portal-contracts` | alias |
| `--remote`, `--remote-prompt`, `--remote-workers`, `--remote-rate` | `--remote-host`, `--remote-password-prompt`, `--remote-connections`, `--remote-scan-delay` | alias |
| `--remote-user`, `--remote-password`, `--remote-dir`, `--remote-debug` | same | same |
| `--vtkey --vtmode --vtscore --vtaccepteula --vtwaitforquota --vtverbose` | `--vt-key --vt-mode --vt-score --vt-accept-eula --vt-wait-quota --vt-verbose` | hidden alias |

## 13. Removed in v11

| v10 flag | v11 behaviour | Replacement |
|---|---|---|
| `--thunderstorm` | parses, prints a pointer, exits 1 | `tools/thunderstorm` (Linux package) |
| `--server-host --server-port --server-cert --server-key --server-upload-dir --server-store-samples --server-result-cache-size --sync-only-threads` | unknown flag | Thunderstorm binary options |
| `--bifrost2Server`, `--bifrost2Score`, `--bifrost*` | unknown flag | none (Bifrost removed) |
| `--encrypt` | unknown flag | `--encryption-key` |
| `--printlicenses` | unknown flag | `--list-licenses` |
| `--nocolor`, `--showall` | unknown flag | `--no-color`; `--match-limit 0` (hit cap) / `--show-all` or `--lab` (Sigma muting) |
| `--action_command`, `--action_args`, `--action_level` | deprecated, no effect | plugins |
| `--jsonv2`, `--sigma`, `--timestomp`, `--buffer_size`, `--nolockthread`, `--split-registry-keys` | deprecated, no effect | none needed |
| `--notice`, `--warning`, `--alert` | deprecated, no effect | `--min` |
| (not a v10 flag) `--hex-matches` | v11 only, deprecated, no effect | none needed |
| `--deepdive`, `--deepdivecustom` | never existed in 10.7 either (manual error) | `-m/--image_file` (v10), `--memory-dump-file` (v11) |

## 14. New in v11 (no v10 equivalent)

`--target-os`, `--exclude-path`, `--exclude-registry-key`, `--exclude-eventlog`, `--exclude-process`,
`--no-builtin-path-excludes` (implied by `--deep`/`--files-all`), `--exclude-component`, `--no-json`, `--text`,
`--log-object TYPE[:LIMIT]`, `--describe-object-type`, `--log-size-limit`, `--sigma-ruleset`, `--no-plugins`,
`--plugin-development-mode`, `--cobaltstrike-beacons`, `--list-licenses`, `--list-deepscan-criteria`,
`--no-tui`, `--tui-buffer-size`, `--tui-replay-lines`, `--no-color`, `--no-system-ca`, `--help short|long|detailed`.
