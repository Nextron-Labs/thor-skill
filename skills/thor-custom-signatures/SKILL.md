---
name: thor-custom-signatures
description: Creates, deploys and tests custom detection content for THOR 10 and THOR 11 in the custom-signatures folder - simple IOC files (hash, filename, c2/domains, keyword, mutex/event handles, named pipes, trusted hashes), THOR 11 YAML IOCs, YARA rules (generic, meta, keyword, registry, log, process; externals like filepath/extension/filetype, meta score/limit, DEEPSCAN and FORCE tags), Sigma rules (log-based on EVTX/log files and THOR 11 object-based rules with logsource service THOR), STIX v2 indicators, false_positive_filters.cfg, signature selection flags (--customonly, --custom-signatures-only, --print-signatures, --list-signatures, --init-selector, --signature-include) and `thor-util encrypt`. Use when a user writes IOCs or rules for THOR, converts threat intel into THOR signatures, asks why a custom IOC/YARA/Sigma rule does not load or fire, or wants to suppress false positives.
compatibility: THOR 10.7.x and THOR 11.0.x, all platforms, incl. THOR Lite (Sigma limits in Lite 10). Rules added by plugins are covered by the thor-plugins skill.
metadata:
  author: Nextron Systems
  version: "2.0"
---

# THOR custom signatures

Turn indicators into files THOR loads at start-up, prove they load, prove they fire on a sample.
Detect the THOR version first (`thor --version` banner, `thor10.db` vs `thor.db`, JSON `log_version`); if
unknown, ask once. Layout, flags and several semantics differ between 10 and 11.

## 1. Where files go

`custom-signatures/` is resolved next to the **THOR binary**, not the current directory. Loaders walk
recursively, skip hidden files (`.name`) and match extensions case-insensitively.

| Content | THOR 10 | THOR 11 (subfolder is mandatory) |
|---|---|---|
| IOC files `.txt` `.cfg` / encrypted `.dat` | anywhere below `custom-signatures/` | `custom-signatures/iocs/` (or `misc/`) |
| YAML IOCs `.yml` `.yaml` / `.yms` `.yams` | not supported | `custom-signatures/iocs/` |
| YARA `.yar` `.yara` `.yarx` / `.yas` `.yasx`; precompiled `.yac`; deep-only `.yare` `.yase` `.yace` | anywhere | `custom-signatures/yara/` |
| Sigma `.yml` / `.yms` (`.yaml` is **not** loaded as Sigma) | anywhere | `custom-signatures/sigma/` |
| STIX v2 `.json` / `.jsos` | anywhere | `custom-signatures/stix/` |

- THOR 11 ignores files in the `custom-signatures/` root and in wrong subfolders, silently.
- THOR 10 parses every `.yml` as Sigma and every `.json` as STIX wherever it sits.
- `thor-util upgrade` from 10 to 11 moves files by extension: `.yar/.yara/.yas`→`yara/`, `.yml/.yaml/.yms`→`sigma/`
  (a moved `.yaml` then does not load), `.json/.jsos`→`stix/`, `.txt/.dat`→`iocs/`. Check YAML IOCs and `.cfg` afterwards.
- YARA Forge rules live in `custom-signatures/yara-forge/` (10) or `custom-signatures/yara/yara-forge/` (11), so
  they count as custom and stay active with `--customonly`.
- Packages ship commented templates in `custom-signatures/iocs/templates/` (`*.txt.template`, not loaded; copy and rename to `.txt`).

## 2. IOC files

**Simple IOC files** (`.txt`; deprecated in THOR 11 in favour of YAML IOCs, still loaded). The **file name** decides
the type. A tag matches as a whole word: regex `(^|[^A-Za-z])TAG($|[^A-Za-z])` on the lowercased basename including
the extension, so digits, `_`, `-`, `.` are separators (`apt1c2.txt` = c2, `my_c2_iocs.txt` = c2,
`imphash.txt` = **nothing**, `myc2iocs.txt` = nothing). First matching type wins in this order:

| Order | Type | Tags | Line format | Default score |
|---|---|---|---|---|
| 1 | Keyword | `keyword` `keywords` | one case-sensitive string per line | 70 |
| 2 | Filename | `filename` `filenames` | `REGEX;SCORE` or `REGEX;SCORE;FP_REGEX` | as given (negative allowed) |
| 3 | Hash | `hash` `hashes` `md5s` | `HASH`, `HASH;DESC`, `HASH;SCORE;DESC` | 100 |
| 3a | Trusted hash | hash tag **and** `trusted` or `falsepositive` | as hash | v10: drops the file finding; v11: score -100 |
| 4 | C2 | `c2` `domains` | `DOMAIN-IP-CIDR` or `…;SCORE`; preceding `# comment` = description | 75 |
| 5 | Named pipe | `pipe` `pipes` `namedpipe` `namedpipes` | `PIPE;DESC` or `PIPE;SCORE;DESC` (no `\\.\pipe\` prefix) | 100 |
| 6 | Mutex/Event | `mutexes` `events` `handles` | `NAME;DESC` (lines without `;` skipped) | 70 (v10 Events module 75) |

Pitfalls: `c2-keywords.txt` loads as keyword; `false-positive-hashes.txt` and `whitelist-hashes.txt` load as
**malicious** hashes; a file without tag is skipped (v11 warns "Custom IOC file won't be loaded since it contains no
supported IOCs"). Hash length must be 32/40/64 (MD5/SHA1/SHA256; imphash is a 32-char entry).

**Filename IOC semantics**: column 1 without regex metacharacters (`.+*?()|[]{}^$`, `\d` …) is a plain string
matched **case-insensitively** as substring (`\\PsExec\.exe` counts as plain: every special char is escaped).
Otherwise it is a regex, case-sensitive unless `(?i)` appears anywhere. Column 3 (FP regex) is always
case-insensitive. Filename IOCs match anywhere in the full path (v10: also in registry, log, task, service strings;
v11: in all fields of all objects). Write Windows paths with `\\`; on Unix targets THOR converts separators
(v10 `--cross-platform`, v11 `--target-os`/`--cross-platform-paths` for images).

**THOR 11 YAML IOCs** (`custom-signatures/iocs/*.yml`, type from content, not file name): keys `files`, `c2s`,
`hashes`, `named_pipes`, `mutexes`, `events` (no keywords). Each entry: `value` (string or list), `type: plain|regex`,
`case_sensitive`, `score` (**set it**: omitted = 0), `false_positives`. Details and examples:
[references/simple-iocs.md](references/simple-iocs.md).

Where IOCs apply: hashes only on files that get a content (deep) scan, plus AmCache SHA1; C2 on connections, DNS
cache, hosts, firewall, log/event lines (process memory only with `--c2-in-memory` / v11 `--c2-memory-analysis`);
C2 domain IOCs are substring matches (`evil.com` also hits `notevil.com`).

## 3. YARA rules

Rule type comes from the **file name** (same whole-word logic, but digits are word characters), first match wins:

| Tag in file name | Type | Applied to |
|---|---|---|
| `log` `logs` | log | log lines, EVTX/Eventlog entries, journald, audit log |
| `registry` | registry | registry values/keys (`KEYPATH;VALUENAME;VALUE`, no `HKLM` prefix) |
| `keyword` `keywords` | keyword | every non-file element as text (process command lines, services, tasks, log lines …) |
| `process` `memory` | process | process memory, memory dumps, DeepDive chunks |
| `meta` `deepscan` | meta | **every** file: first 2048 bytes (v10) / 64 KB (v11) + externals; dirs and symlinks too (v11) |
| none | generic | files **selected for deep scan**; custom generic rules also run on process memory |

**Deep-scan gating (most common "my rule never fires")**: in default mode generic YARA rules, hash IOCs and STIX
only run on files chosen by the built-in `DEEPSCAN` meta rules (interesting extensions/magic, size). Every file is
deep-scanned only with `--intense`/`--allfiles` (v10) or `--deep`/`--files-all` (v11). To force selection add a
meta rule tagged `DEEPSCAN` in a file named `*meta*.yar`; add tag `FORCE` to bypass the file size limit. Rules that
only use externals (`extension`, `filepath`, `filename`) belong in a meta file. v11: `--list-deepscan-criteria`.

Meta attributes THOR honours: `score` (int, default 75, negative allowed), `falsepositive` (any value **negates**
the score), `limit = "<Module or feature>"` (exact name, e.g. `Filescan`, `ProcessCheck`; an unknown name silences
the rule everywhere), `nodeepdive = 1`, `type = "file"` (skipped in process scans only; `type = "memory"` does
nothing), `description`/`author`/`reference`/`date`. Strings named `$fp*` are hidden from output. Global rules are
refused; duplicate rule names break the file. Externals (generic + meta): `filename`, `filepath` (**directory**,
no trailing separator), `extension` (lowercase with dot), `filetype` (magic type: `EXE`, `ZIP` …), `filemode`,
`owner`, `group`, `age` (days since creation), `md5` (generic only), `unpack_parent`, `unpack_source`
(`EMAIL>ZIP` chain), `timezone`, `language`, `osversion`; v11 adds `permissions`.

Engine: libyara 4.5.x in both versions (`thor --version` prints it); v10 builds include `dotnet` but not `magic`/`cuckoo`.
Do not use YARA-X-only syntax. Test with `yara` 4.5 and `-d` for externals before deploying.
Details: [references/yara-rules.md](references/yara-rules.md); examples: [examples/yara-enhanced.md](examples/yara-enhanced.md).

## 4. Sigma rules

- **Log-based (v10 and v11)**: standard SigmaHQ log sources (`product: windows` + `service: security|system|…`)
  applied to live Eventlog and to `.evtx`/log files found by Filescan, via THOR's built-in mapping. Custom log
  sources (e.g. your own log files) go into `config/sigma.yml`. v10 also applies `category: process_creation`
  rules to running processes (fields `Image`, `CommandLine`, `User`, `ParentImage`, `ParentCommandLine`).
- **Object-based (v11 only)**: any THOR object (process, autorun entry, Windows service, cron job, scheduled task,
  file …). Exact form, case-sensitive:
  ```yaml
  logsource:
      service: THOR
      category: Windows service      # object type name exactly as THOR spells it
      product: windows               # optional: OS of the scanned host
  ```
  Field names are the lowercase JSON names joined with dots (`image.path`, `command`, `parent_info.exe`,
  `commands.0.command`). The old `product: THOR` + `service: <type>` form and UPPERCASE fields never match.
  A misspelled `category` gives no error. Get names with `--describe-object-type "<type>"`.
- **Loading**: rules below the minimum level are dropped at load time, custom rules included. Default `high`
  (`medium` with `--intense`/`--deep`). Lower it with `--minimum-sigma-level medium` (v10) or `--sigma-threshold
  medium` (v11), or in v11 give the rule a `score: <int>` field (overrides level score, bypasses the threshold).
  Score by level: low 40, medium 50, high 70, critical 100. `status: deprecated` is skipped.
- **Lite**: THOR Lite 10 skips Sigma unless the license includes it (Cloud Lite); THOR Lite 11 enables Sigma.

Details and log-source config: [references/sigma-rules.md](references/sigma-rules.md); working v11 rules:
[examples/sigma-object-rules.md](examples/sigma-object-rules.md).

## 5. STIX v2

Bundles of `indicator` objects; only `pattern` (+ name/description/labels) is used. File observables (name,
parent directory, MD5/SHA1/SHA256, size, times) apply to deep-scanned files; registry observables on Windows only.
Fixed score 75. One invalid JSON file disables **all** STIX (built-in too). Details:
[references/stix-iocs.md](references/stix-iocs.md).

## 6. False positives

| Tool | Effect |
|---|---|
| Negative-score IOC or rule (`\\SysInternals\\PsExec\.exe;-60`, YARA `score = -50`) | multiplies the remaining uncertainty: 60 and -60 give 36, but 100 and -60 stay 100. Only a subscore <= -100 forces the total to 0 |
| Trusted hash file (`trusted-hashes.txt`) | v10 drops the whole file finding; v11 -100 |
| `config/false_positive_filters.cfg` | one Go regex per line, `#` comments, **case-sensitive**; a matching message is dropped entirely. Matched against the text-log rendering `MODULE: … MESSAGE: … FILE: …` (uppercase keys, both versions). Escape backslashes, prefer a distinctive value (path, rule name) |
| Excludes | v10 `config/directory-excludes.cfg` etc.; v11 `--exclude-path` (and `path-excludes.cfg`): case-insensitive regex, element not scanned at all |

## 7. Selection flags

| Purpose | THOR 10 | THOR 11 (old name still accepted) |
|---|---|---|
| only custom signatures (+ built-in deepscan/PEiD rules, magic headers) | `--customonly` | `--custom-signatures-only` |
| load only signatures containing text | `--init-selector X` | `--signature-include X` |
| drop signatures containing text | `--init-filter X` | `--signature-exclude X` |
| list loaded signatures and exit (no STIX) | `--print-signatures` | `--list-signatures` |
| minimum Sigma level | `--minimum-sigma-level` | `--sigma-threshold` |
| disable a type | `--nosigma` `--noyara` `--nostix` | `--no-sigma` `--no-yara` `--no-stix-iocs` |

Selectors/filters are case-insensitive substring tests on rule name/tags/description (IOCs: description/title)
and also hit built-in deepscan rules: `--init-selector X` can silently stop content scanning unless every file
is deep-scanned. `--customonly` also disables built-in heuristics (filename typo check, malicious TLDs).

## 8. Encryption

`thor-util encrypt <file|glob> [more files] [--destdir DIR]` (positional; there is no `--file` flag).
Mapping: `.yar/.yara/.yac`→`.yas`, `.yml/.yaml`→`.yms`, `.txt`→`.dat`, `.json`→`.jsos`; existing targets get a
`2_` prefix. Deploy only the encrypted file and keep the plaintext off the target. `thor-util decrypt` is for
logs, not signatures.

## 9. Test safely (always before deployment)

Never test with an unrestricted scan. Use a small folder with a sample, custom signatures only, every file
deep-scanned, no ThorDB, separate output dir, and filter license lines:

```bash
# THOR 10
./thor-linux-64 --customonly -a Filescan -p /tmp/sigtest --intense --nothordb -e /tmp/thor-out \
  | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'
# THOR 11
./thor-linux-64 --custom-signatures-only --module Filescan --path /tmp/sigtest --deep --no-thordb -e /tmp/thor-out \
  | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'
```
Windows: `thor64.exe` with the same flags. First check loading only: `--print-signatures` (10) /
`--list-signatures` (11) `| grep -i <rule-name>`. Startup lines to look for:
`Reading iocs from … as 'filename' type` (v11 also `Loaded IOCs from custom IOC file` with TYPE),
`Adding rule set from x.yar as 'meta' type` / `as 'default' and 'custom' type`, `Successfully compiled N … rules`,
errors `Could not load yara signature file`, `Could not parse rules from Sigma file`, `Could not add Sigma rule`.
For EVTX/log Sigma rules put the exported `.evtx`/`.log` in the test folder (Filescan parses them).
For v11 object rules run only the producing module (`--module ServiceCheck|Autoruns|ProcessCheck|Cron …`) with
`--no-thordb`, and see real field values with `--log-object "<type>:5" --console-json`, piped through the same
license filter (the JSON `Scan Information` line carries `license.owner`).

## 10. "My signature doesn't fire" checklist

1. Right folder for the version (v11 subfolders) and next to the binary that runs?
2. Startup log shows the file with the intended type? File name tag correct (whole word, precedence)?
3. Generic YARA / hash / STIX on a file that was not deep-scanned? Test with `--deep`/`--intense`.
4. File above the size limit (v10 30 MB, v11 64 MB default)? Meta rule + `FORCE`, or raise `--max_file_size` / `--file-size-limit`.
5. Sigma level below threshold, wrong object logsource form, UPPERCASE fields, `.yaml` extension?
6. Score below the reporting threshold (`--min`, default 40)? Filtered by a selector, FP filter or exclude?
   Alert needs total >= 81 and at least one subscore >= 76, in both versions (else Warning).
7. YARA externals: `filepath` is the directory; compare paths case-insensitively (`/…/i` or `icontains`).

## Reference files

- [references/simple-iocs.md](references/simple-iocs.md) - every IOC type, line formats, YAML IOCs, where each IOC is applied.
- [references/yara-rules.md](references/yara-rules.md) - rule types, deep scan, meta attributes, externals, bulk scanning, directives.
- [references/sigma-rules.md](references/sigma-rules.md) - log sources, `config/sigma.yml`, object types and fields, levels, testing.
- [references/stix-iocs.md](references/stix-iocs.md) - supported observables, operators, syntax traps.
- [examples/hash-iocs.md](examples/hash-iocs.md), [examples/filename-iocs.md](examples/filename-iocs.md) - ready IOC files.
- [examples/yara-enhanced.md](examples/yara-enhanced.md) - YARA with externals, meta/DEEPSCAN, registry/log/keyword rules.
- [examples/sigma-object-rules.md](examples/sigma-object-rules.md) - tested THOR 11 object rules (service, autorun, cron, process).
