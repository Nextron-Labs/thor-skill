# IOC files (simple `.txt` and THOR 11 YAML)

Read this when writing or debugging IOC files. Folder: THOR 10 anywhere below `custom-signatures/`;
THOR 11 `custom-signatures/iocs/` (or `misc/`). Root-level files are ignored by THOR 11.

## 1. Simple IOC files: type from file name

- Extensions: `.txt`, `.cfg` (plain), `.dat` (encrypted with `thor-util encrypt`).
- Tag test: regex `(^|[^A-Za-z])TAG($|[^A-Za-z])` against the **lowercased basename incl. extension**.
  Separators are anything but letters: `-`, `_`, `.`, digits, start/end of name.
- First match wins: keyword, filename, hash, (file-type-signatures), c2/domains, named pipes, handles.
- Lines: empty lines and lines starting with `#` are skipped. In keyword, filename and C2 files the last `# comment`
  becomes the description of the following IOCs (default "not set").

| File name | Loaded as | Why |
|---|---|---|
| `case22-c2-iocs.txt`, `apt1c2.txt` | C2 | `c2` surrounded by non-letters |
| `myc2iocs.txt`, `filenameiocs.txt` | nothing | tag glued to letters |
| `imphash-iocs.txt` | nothing | `imphash` is not the word `hash`; use `imp-hash-iocs.txt` |
| `c2-keywords.txt` | keyword | keyword is checked before C2 |
| `my-trusted-hashes.txt`, `falsepositive-hashes.txt` | trusted hashes | hash tag + `trusted`/`falsepositive` |
| `false-positive-hashes.txt`, `whitelist-hashes.txt` | **malicious** hashes | no `trusted`/`falsepositive` word |
| `trusted.txt` | nothing | no hash tag |

Untagged files: THOR 10 warns only for files under `custom-signatures/iocs` ("no file name indicator matched");
THOR 11 warns "Custom IOC file won't be loaded since it contains no supported IOCs".

## 2. Formats per type

### Hashes (`hash`, `hashes`, `md5s`)
```text
# HASH                      -> score 100, no description
# HASH;DESCRIPTION          -> score 100
# HASH;SCORE;DESCRIPTION    -> custom score (if SCORE is not an int: score 100, cols 2+3 = description)
0c2674c3a97c53082187d930efb645c2;Sakula loader
f05b1ee9e2f6ab704b8919d5071becbce6f9d0f9d0ba32a460c41d5272134abe;50;Vulnerable driver
```
- Length must be 32, 40 or 64 hex chars (others dropped; error in v11). Case-insensitive.
- MD5, SHA1, SHA256 of scanned files; a 32-char entry also matches imphash (v10: EXE files unless `--noimphash`;
  v11 also RichHeaderHash). AmCache SHA1 entries are checked too.
- Only files that get a content (deep) scan are hashed: default mode = files selected by DEEPSCAN rules; use
  `--intense`/`--allfiles` (v10) or `--deep`/`--files-all` (v11) to hash every file.
- Trusted hash files: v10 drops the entire file finding (including filename IOC and YARA reasons); v11 sets score
  -100, which forces the element's total to 0.

### Filenames (`filename`, `filenames`)
```text
# REGEX;SCORE
# REGEX;SCORE;FALSE_POSITIVE_REGEX
\\nc\.exe;60
\\SysInternals\\PsExec\.exe;-60
\\PsExec\.exe;60;\\SysInternals\\
([C-Zc-z]:\\|\\\\).{1,40}\\svchost\.exe;65;(?i)(System32|SysWOW64|winsxs)\\
```
- Plain vs regex: no unescaped metacharacter (`. + * ? ( ) | [ ] { } ^ $`) and no class escape (`\d \w \s \b`
  …) = **plain string**, escapes removed, matched case-insensitively as a substring. `\\nc\.exe` is therefore plain
  `\nc.exe`, case-insensitive. Anything else is a regex: case-sensitive unless `(?i)` occurs anywhere (then the
  whole pattern is case-insensitive).
- Column 3 is always case-insensitive and is tested on the same string that matched.
- Legacy `REGEX;COMMENT` (non-numeric column 2) loads with score 60; a line without column 2 is an error.
- Negative scores lower the total score of the element (use for known-good locations).
- Matching is unanchored. v11 rewrites `^`/`$` so they work per field/line and makes regexes non-greedy.
- Applied to: v10 full file paths (Filescan, Prefetch, WER) and every string checked by keyword logic (registry,
  services, tasks, Eventlog, log lines); v11 every field of every object.
- Separators: write Windows style `\\`. v10 converts `\\` to `/` on Unix and adds both forms with
  `--cross-platform`; v11 follows `--target-os` / `--cross-platform-paths`.
- v10: an identical column-1 string in a custom file overrides the built-in entry's score (custom files load first).
- Built-in heuristic (basename one typo away from a system binary, +60) is disabled by `--customonly`.

### C2 (`c2`, `domains`)
```text
# Operation X infrastructure        <- becomes the description
update-check.example.net
89.22.123.12
203.0.113.0/24;70
```
- `INDICATOR` or `INDICATOR;SCORE`, default score **75** (the manual says 100). Non-integer score
  drops the line.
- Domain IOCs are **substring** matches (verified for v10): `evil.com` also matches `notevil.com`. Prefer full
  hostnames for short or generic domains.
- IPs: exact match or CIDR containment; very wide CIDRs (> 16 host bits) produce a warning and cost performance.
- Applied to: process connections, DNS cache, hosts file, firewall rules, Eventlog/EVTX, log lines, audit log and
  journald (v11 also web history). Process memory only with `--c2-in-memory`/`--custom-c2-in-memory` (v10) or
  `--c2-memory-analysis`/`--custom-c2-memory-analysis` (v11).

### Keywords (`keyword`, `keywords`)
```text
# Strings from the case
sekurlsa::logonpasswords
Invoke-Mimikatz
```
- One plain, case-sensitive string per line, score 70. v10 matches as whole word (`fullword`), v11 as substring.
- Applied to all non-file elements rendered as text (command lines, services, tasks, log lines, registry).
- THOR 11 deprecates keyword IOCs: prefer a keyword-type YARA rule (`*-keyword.yar`) or Sigma.

### Mutexes and events (`mutexes`, `events`, `handles`)
```text
Global\mymaliciousmutex;Operation Fallout RAT mutex
Dwm-[a-f0-9]{4}-ApiPort-[a-f0-9]{4};Campaign loader
```
- `NAME;DESCRIPTION` only (no score column; lines without `;` are skipped). Score 70 (v10 Events module 75).
- Plain = **equals** on full name or basename; regex = unanchored. Case-sensitive. `\BaseNamedObjects\` is treated
  as `Global\`.
- Windows only (Mutex and Events modules, process handles), unless cross-platform path handling is enabled.

### Named pipes (`pipe`, `pipes`, `namedpipe`, `namedpipes`)
```text
MyMaliciousNamedPipe;Known RAT pipe
MyInteresting[a-z]+Pipe;50;Suspicious pattern
```
- `PIPE;DESC` or `PIPE;SCORE;DESC` (default 100). No `\\.\pipe\` prefix.
- Plain = case-insensitive equals on basename or full name; regex = case-insensitive, unanchored.
- Windows only (Pipes module).

## 3. THOR 11 YAML IOC files (recommended format in 11)

`custom-signatures/iocs/<name>.yml` (`.yaml`; encrypted `.yms`/`.yams`). The type comes from the keys, not the file
name. One file can mix types. Spec version 2.x (`version` empty = current; other major = file rejected).

```yaml
title: Case 2026-11 Loader Campaign
id: 5d1c7a40-2f3e-4b1a-9c8d-0e6f4a2b7c11
version: 2.0.0
description: IOCs from incident 2026-11
author: Your Name
date: 2026-11-16
references:
  - https://example.org/report
tags:
  - case-2026-11
iocs:
  hashes:
    - value:
        - 0c2674c3a97c53082187d930efb645c2
        - f05b1ee9e2f6ab704b8919d5071becbce6f9d0f9d0ba32a460c41d5272134abe
      score: 100
    - value: d41d8cd98f00b204e9800998ecf8427e      # known good
      score: -100
  files:
    - value: \ProgramData\updsvc\svch0st.exe        # plain substring, case-insensitive
      score: 80
    - value: '\\Users\\Public\\[a-z]{8}\.(exe|dll)$'
      type: regex
      score: 70
      false_positives:
        - value: \Users\Public\Documents\
  c2s:
    - value:
        - update-check.example.net
        - 203.0.113.0/24
      score: 90
  named_pipes:
    value: MsUpdPipe_7f3a
    score: 80
  mutexes:
    value: Global\LoaderMtx2026
    case_sensitive: true
    score: 85
```
- Keys under `iocs`: `files`, `c2s`, `hashes`, `named_pipes`, `mutexes`, `events`. There is no keyword key.
- Each entry (single map or list): `value` (string or list), `type: plain|regex` (default plain), `case_sensitive`
  (default false), `score` (**no default: omitted = 0, i.e. no effect**), `false_positives` (same keys).
- Hashes: plain only; `false_positives` on hashes is an error.
- YAML quoting: plain scalars keep backslashes literally; use single quotes for regexes (no escape processing).
- `--signature-include/--signature-exclude` test against title + tags + references.

## 4. Verify loading

`--print-signatures` (10) / `--list-signatures` (11) lists loaded IOCs (not STIX; v10 omits handles). Startup log:
`Reading iocs from <path> as 'filename' type` (also `'hash'`, `false positive 'hash'`, `'keyword'`, `'domains'`,
`'pipes'`, `'handles'`), v11 `Loaded IOCs from custom IOC file` with `TYPE`, then totals such as
`Successfully compiled N filename ioc strings and M filename ioc regexs`, `… malware and M false positive hashes`,
`… malware domains`.
