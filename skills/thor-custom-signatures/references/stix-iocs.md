# STIX v2 indicators

Read this when importing STIX 2 bundles (MISP, OpenCTI and other TIPs export them) or when STIX indicators
do not load. STIX 1.x (XML) is not supported.

## 1. Placement and loading

| | THOR 10 | THOR 11 |
|---|---|---|
| Folder | anywhere below `custom-signatures/` (every `.json` there is parsed as STIX) | `custom-signatures/stix/` only |
| Extensions | `.json`, encrypted `.jsos` | same |
| THOR Lite | not available in Lite 10 | available |

- Only bundle `objects` with `"type": "indicator"` are used, and of those only `pattern`, `name`, `description`,
  `labels`, `indicator_types`. `pattern_type`, `valid_from`, `valid_until`, observables and relationships are
  ignored; there is no expiry.
- **One unreadable or invalid JSON file aborts the whole STIX load**, built-in indicators included
  ("Could not init stix rulehub"). Validate JSON before deploying (`python3 -m json.tool file.json`).
- An indicator whose pattern does not compile is skipped and logged only at Debug level; the summary says
  `Successfully compiled N STIXv2 indicators (skipped M indicators)`. If M > 0, run with `--debug` to see why.
- Startup: `Adding STIXv2 indicators from <file>`. `--print-signatures`/`--list-signatures` do not list STIX.
- Every match scores a fixed **75** (no per-indicator score). Selectors/filters test name + description + labels.

## 2. Where indicators are applied

- File observables: in Filescan, only on files that get a deep scan (default mode: files selected by DEEPSCAN
  rules; every file with `--intense`/`--allfiles` (10) or `--deep`/`--files-all` (11)).
- Registry observables: Windows registry (live or hives) only.

## 3. Supported object paths and operators

| Object path | Operators | Compared value |
|---|---|---|
| `file:name` | `=` `!=` `LIKE` `MATCHES` | basename |
| `file:parent_directory_ref.path` | `=` `!=` `LIKE` `MATCHES` | directory **with trailing separator** (`C:\Users\bob\AppData\Local\Temp\`) |
| `file:hashes.'SHA-256'` / `.sha256`, `file:hashes.'SHA-1'` / `.sha1`, `file:hashes.'MD5'` / `.md5` / `.md-5` | `=` `!=` | hex, case-insensitive |
| `file:size` | `=` `!=` `<` `<=` `>` `>=` | bytes |
| `file:created` (birth time), `file:modified`, `file:accessed` | `=` `!=` `<` `<=` `>` `>=` | timestamp |
| `win-registry-key:key` | `=` `!=` `LIKE` `MATCHES` | key path |
| `win-registry-key:values.name` | `=` `!=` `LIKE` `MATCHES` | value name |
| `win-registry-key:values.data` | `=` `!=` `LIKE` `MATCHES` | value data |
| `win-registry-key:modified` | time comparators | key last-write time (not `values.modified_time`, which the v10 manual shows) |

## 4. Syntax traps (verified against THOR's STIX parser)

- `=` / `!=`: case-insensitive exact comparison.
- `LIKE`: converted to an **anchored**, **case-sensitive** regex (`%` = any string, `_` = one character; `\%`, `\_`
  escape them). `file:name LIKE 'UPDATE%'` does not match `update7.exe`.
- `MATCHES`: Go regular expression, unanchored, case-sensitive; add `(?i)` for case-insensitive matching.
- Time literals need the `t` prefix and second precision: `t'2026-11-01T00:00:00Z'`. A plain string
  (`'2026-11-01T00:00:00Z'`) fails to compile. `<=` and `>=` behave like `<` and `>` for times.
- `AND`/`OR` work **only inside one `[...]`**. `[a] AND [b]`, `FOLLOWEDBY`, `REPEATS`, `WITHIN` are rejected.
- String literals are `'...'`; a literal must not end with a backslash (`'C:\Temp\'` breaks tokenizing).
- Backslashes are not unescaped by the pattern parser. In the JSON file `\\` is one backslash in the pattern:
  - `=` and `LIKE`: write one backslash per path separator in the pattern (`"%\\CurrentVersion\\Run"` in JSON).
    In `LIKE`, a backslash directly before `%` or `_` escapes it, so `'%\Temp\%'` never matches; use `MATCHES`.
  - `MATCHES`: a literal backslash is `\\` in the regex, i.e. `\\\\` in JSON.

## 5. Working bundle (tested with THOR 11's parser)

```json
{
  "type": "bundle",
  "id": "bundle--6a1f0c3e-2b4d-4e8f-9a7c-1d2e3f4a5b6c",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--0f6c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e01",
      "name": "Loader SHA256",
      "description": "Stage 1 loader from case 2026-11",
      "labels": ["malicious-activity"],
      "pattern": "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
      "pattern_type": "stix",
      "valid_from": "2026-11-01T00:00:00Z"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--0f6c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e02",
      "name": "Numbered updater in a Temp folder",
      "pattern": "[file:name MATCHES '^update[0-9]+\\.exe$' AND file:parent_directory_ref.path MATCHES '(?i)\\\\temp\\\\$']",
      "pattern_type": "stix",
      "valid_from": "2026-11-01T00:00:00Z"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--0f6c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e03",
      "name": "Small recent update7.exe",
      "pattern": "[file:name = 'update7.exe' AND file:size < 100000 AND file:modified > t'2026-11-01T00:00:00Z']",
      "pattern_type": "stix",
      "valid_from": "2026-11-01T00:00:00Z"
    },
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--0f6c1d2e-3a4b-4c5d-8e9f-0a1b2c3d4e04",
      "name": "Run key value MalwareUpdater",
      "pattern": "[win-registry-key:key LIKE '%\\CurrentVersion\\Run' AND win-registry-key:values.name = 'MalwareUpdater']",
      "pattern_type": "stix",
      "valid_from": "2026-11-01T00:00:00Z"
    }
  ]
}
```

## 6. Converting TIP exports

- Keep only indicators with patterns from the table above; drop `network-traffic`, `domain-name`, `url`, `email`
  patterns (put domains/IPs into a C2 IOC file instead) and split `[a] AND [b]` into one bracket.
- Rewrite time literals to `t'…Z'`, and path `LIKE` expressions that end in `\%` to `MATCHES`.
- Encrypt for deployment: `thor-util encrypt intel.json` → `intel.jsos`.
