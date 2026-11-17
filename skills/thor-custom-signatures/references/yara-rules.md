# YARA rules in THOR

Read this when writing YARA rules for THOR or debugging why one does not load or match.
Folder: THOR 10 anywhere below `custom-signatures/` (convention `custom-signatures/yara/`); THOR 11 only
`custom-signatures/yara/` (recursive).

## 1. Files and extensions

| Extension | Meaning |
|---|---|
| `.yar` `.yara` `.yarx` | plain source |
| `.yas` `.yasx` | encrypted source (`thor-util encrypt`) |
| `.yac` | precompiled rules (`yarac`), loaded as-is: no filtering, no validation |
| `.yare` `.yase` `.yace` | as above, but loaded only with `--intense` (10) / `--deep` (11) |

- A custom file that fails to compile is skipped with Error `Could not load yara signature file` (message contains
  `rule X (line N)`); the scan continues. Rules from all files of one type are compiled together: duplicate rule
  names across custom files of the same type break one of them.
- Rules declared `global` are refused ("would impact THOR's built-in signatures"). `private` rules are fine.
- Comment directives (own line): `/* VAR:name,type,default */` defines an extra external (`boolean|float|int|string`);
  `/* MIN_THOR_BUILD:YYYYMMDD */` skips the file on older builds.
- `uuid` meta: a second rule with the same uuid in the same rule type is skipped.

## 2. Rule type from the file name

Whole-word test on the lowercased file name, separators are any non-alphanumeric character (`-`, `_`, `.`), so
`apt-registry.yar` is registry but `myregistryrules.yar` is generic. Checked in this order, first hit wins:

| Order | Tag | Type | Scanned data |
|---|---|---|---|
| 1 | `log`, `logs` | log | text log lines, Windows Eventlog/EVTX entries, journald, Linux audit log |
| 2 | `registry` | registry | registry data (live and hives) |
| 3 | `keyword`, `keywords` | keyword | every non-file element as text: process command lines, services, tasks, autoruns, registry, log lines, mutexes … |
| 4 | `process`, `memory` | process | process memory, memory dumps (`--memory-dump-file`), DeepDive chunks |
| 5 | `meta`, `deepscan` | meta | every file: first 2048 bytes (v10) / first 64 KB (v11, hidden `--metarule-scan-limit`) + externals |
| 6 | none | generic | files selected for deep scan; custom generic rules also on process memory, dumps, DeepDive |

Examples: `incident-feb17.yar` generic, `case-a23-process-rules.yar` process, `custom-meta.yar` meta,
`redkitten-tasks-keyword.yar` keyword, `incident-feb17-registry.yar` registry, `event-log-rules.yar` log.

Startup log per file: `Adding rule set from <name> as '<type>' type` (custom generic: `as 'default' and 'custom'
type`). With `--customonly` built-in files named `deepscan`/`peid` still load.

What the string looks like:
- **Registry (v10 and v11 per key)**: one line per value `KEYPATH;VALUENAME;VALUE`, no `HKLM`/`HKCU` prefix.
  REG_BINARY = uppercase hex, REG_MULTI_SZ separators `\0`, DWORD/QWORD decimal (0x20 → `32`).
  v11 additionally scans each value object as text (`KEY: <keypath>\<valuename>  VALUE: <data> …`).
- **Event log entries**: `Key1: Value1  Key2: Value2  …` (EventData/UserData fields). **Text logs**: per line.
- **v11 keyword/log rules** see each object as `KEY: value  KEY: value` with uppercase text-log keys (as printed
  by `--log-object` in text mode). Write substring rules; avoid anchors and offsets.
- **Bulk scanning**: registry and log elements are concatenated and pre-scanned with a copy of the rules whose
  false-positive conditions are removed; matching elements are then rescanned one by one with the full rule. Complex
  conditions (loops, `#count`, offsets, `at`) can behave differently in the pre-scan. Keep log/registry rules to
  plain string logic.

## 3. Deep scan selection (who gets generic rules)

- Default mode: generic rules, hash IOCs and STIX run only on files that a built-in **meta rule tagged `DEEPSCAN`**
  selects (executables, scripts, archives, office files … by magic, extension, size). Other files get filename IOCs
  and meta rules only.
- Every file is deep-scanned with `--intense`/`--allfiles` (v10) or `--deep`/`--files-all` (v11).
- Add your own selector in a **meta file** (`custom-deepscan-meta.yar`):
  ```yara
  rule Select_MyFormat : DEEPSCAN {
      meta:
          description = "Deep scan .myo files"
          score = 0
      condition:
          extension == ".myo"
  }
  ```
  `DEEPSCAN` in a generic file does nothing. Add tag `FORCE` (`: DEEPSCAN FORCE`) to scan files above the file size
  limit (v10 default 30 MB, v11 64 MB); this is slow.
- v11: `--list-deepscan-criteria` prints an overview of the selection logic and exits.
- `--init-selector`/`--signature-include` also filter built-in deepscan rules: a selector that excludes them stops
  content scanning in default mode.

## 4. Meta attributes and tags THOR evaluates

| Item | Semantics |
|---|---|
| `score = 80` | integer only (a string is ignored → 75). Default 75. Range -100..100; negative lowers the element score |
| `falsepositive = 1` | presence (any value) multiplies the score by -1. `falsepositive = 1` + `score = -50` gives **+50**: use either a negative score or `falsepositive` with a positive score |
| `limit = "Filescan"` | report the match only in that module/feature (exact name, e.g. `Filescan`, `ProcessCheck`, `Eventlog`, `RegistryChecks`, `Mutex`). An unknown value suppresses the rule everywhere. v11: several `limit` metas = OR |
| `nodeepdive = 1` | ignore matches in DeepDive / memory dump chunks |
| `type = "file"` | match ignored in live process scanning only. `type = "memory"` is **not evaluated** (rule still hits files) |
| `description`, `author`, `reference`, `date`, `modified` | shown in output; description/reference also used by selectors |
| strings `$fp*` | not displayed in the match output |
| tag `DEEPSCAN` (meta files) | select file for generic rules, hash IOCs, STIX |
| tag `FORCE` (meta files) | ignore the file size limit |

To restrict a rule to memory, use the file name tag `process`/`memory` (or `limit = "ProcessCheck"`), not `type`.
DeepDive drops matches with a score below 30.

## 5. External variables (generic and meta rules; for processes they describe the image file)

| Variable | Type | Value |
|---|---|---|
| `filename` | string | basename |
| `filepath` | string | **directory** of the file, no trailing separator (`C:\Temp`, not `C:\Temp\` and not the full path) |
| `extension` | string | lowercase with dot (`.exe`) |
| `filetype` | string | magic header type from `signatures/misc/file-type-signatures.cfg` (`EXE`, `ZIP`, `PDF`, `RAR` …) |
| `filemode` | int | raw file mode |
| `owner`, `group` | string | file owner/group (`group` empty on Windows); for processes `owner` = process user |
| `age` | float | days since file **creation**; NaN if unknown; for processes days since start |
| `md5` | string | MD5 of the file (generic file scan only) |
| `unpack_parent` | string | last unpack step (`ZIP`, `RAR`, `7ZIP`, `EMAIL`, `OLE`, `UPX`, `MFT`, plugin-defined …) |
| `unpack_source` | string | whole chain joined with `>` (`EMAIL>ZIP`) |
| `timezone`, `language` | string | system settings |
| `osversion` | int | Windows build number, 0 elsewhere |
| `permissions` | string | v11 only: Unix mode string or Windows DACL summary |

`filesize` is YARA's built-in. Paths use the scanned system's separators; compare case-insensitively
(`filepath matches /\\temp$/i`, `filepath icontains "\\appdata\\"`). Test locally:
`yara -d filename=a.exe -d filepath='C:\Temp' -d extension=.exe -d filetype=EXE -d age=1.0 rules.yar sample`.

## 6. Engine and syntax

- libyara 4.5.x (`thor --version` prints the version). Write YARA 4 syntax; YARA-X-only features are not supported.
  Validate with `yara` 4.5.x, defining every external you use (`-d`), before deploying.
- v10 builds are compiled with `dotnet` and without `magic` and `cuckoo`; standard modules (`pe`, `math`, `elf`, `time`) are available.
- Performance: avoid unbounded regexes (`.*`, `\w+` without limits), prefer literal strings and `fullword`, avoid
  short atoms. Slow rules hit every deep-scanned file. Bound every repetition: `/[a-zA-Z0-9_]{1,20}\.gif/`, not
  `/\w+\.gif/` (the unbounded form can make YARA crawl on some files).

Workflow for a new rule:
1. Build strings from the sample (strings, code bytes, PE metadata); a generator such as
   [yarGen](https://github.com/Neo23x0/yarGen) gives a starting point that still needs manual review.
2. Give it a unique rule name, a `description` and a `score` that fits its confidence (section 7).
3. Test with the `yara` 4.5.x binary: it must match the sample, and it must stay silent on a clean system's
   program and system folders (`C:\Windows`, `C:\Program Files`, `/usr`) to catch false positives early.
4. Copy it into `custom-signatures/yara/` and check the THOR startup log for `Adding rule set from …` and the
   absence of `Could not load yara signature file`.

Further reading: [YARA performance guidelines](https://gist.github.com/Neo23x0/e3d4e316d7441d9143c7),
[How to write simple but sound YARA rules](https://www.nextron-systems.com/2015/02/16/write-simple-sound-yara-rules/).

## 7. Scoring

- Reported score combines all subscores of an element: sorted descending, each positive one capped at 100 and
  weighted 1/2^i; each negative one multiplies the remaining uncertainty by (1 - s/100), so it cannot
  lower a 100 (100 and -60 = 100; 60 and -60 = 36); any subscore <= -100 forces 0.
- Report level by total score: Notice from 40 (`--min`), Warning from 60, Alert from 81. An Alert also needs at
  least one subscore >= 76, in both versions (two score-60 rules give a Warning). Use `score >= 76` for alert-worthy rules.
- `score = 0` rules are triggers only (DEEPSCAN selectors, plugin hooks).

## 8. Encryption

`thor-util encrypt my-rules.yar` → `my-rules.yas` in the same folder (or `--destdir DIR`). Keep the rule-type tag in
the file name, it survives encryption.
