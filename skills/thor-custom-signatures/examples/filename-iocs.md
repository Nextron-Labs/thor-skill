# Filename IOC examples

File name must contain `filename` or `filenames` as a whole word (`case2611-filename-iocs.txt`). Folder: THOR 11
`custom-signatures/iocs/`; THOR 10 below `custom-signatures/`. Format `REGEX;SCORE` or `REGEX;SCORE;FP_REGEX`.

Rules to remember:
- No regex metacharacter in column 1 = plain substring, **case-insensitive** (`\\PsExec\.exe` is plain:
  every special character is escaped).
- Any metacharacter (`.` `*` `[` `(` `|` `{` `^` `$` …) or class (`\d` `\w`) = regex, **case-sensitive** unless
  `(?i)` appears somewhere in it.
- Column 3 (false-positive regex) is always case-insensitive.
- Write Windows separators as `\\`. Matches anywhere in the path (THOR 11: in every field of every object).

## Tools and malware names: `case2611-filename-iocs.txt`

```text
# Credential dumping tools          <- description for the lines below
\\mimikatz\.exe;100
\\procdump(64)?\.exe;60;\\SysInternals\\
(?i)\\pwdump[0-9]*\.exe;90

# Executables in Temp folders (regex, made case-insensitive)
(?i)\\Temp\\[^\\]+\.exe;50
```

## Same file name, different verdict by location

```text
# PsExec anywhere is suspicious ...
\\PsExec\.exe;60
# ... but expected in the SysInternals folder (negative score)
\\SysInternals\\PsExec\.exe;-60
# One-line alternative: column 3 suppresses the match
\\PsExec64\.exe;60;\\SysInternals\\
```
Scores combine: 60 and -60 give 36 (below Notice, so not reported).

## svchost.exe outside the system folders

```text
([C-Zc-z]:\\|\\\\).{1,40}\\svchost\.exe;65;(System32|SysWOW64|winsxs|servicing)\\
```

## Webshell locations

```text
(?i)\\inetpub\\wwwroot\\.{0,60}\\[a-z0-9]{8}\.aspx$;70
(?i)\\wwwroot\\.{0,60}(cmd|shell)\.aspx?$;90
/var/www/.{0,80}(c99|r57|wso)\.php$;90
```
On Unix targets write Unix paths as shown, or Windows-style `\\` (THOR converts them for the target OS).

## Lowering noise from known directories

```text
\\Windows\\Installer\\;-30
\\ProgramData\\Package Cache\\;-25
\\KnownGoodVendor\\Tool\\;-60
```
Negative filename IOCs reduce, they do not hide: an element with a 100 subscore stays at 100. To hide completely
use an exclude (v10 `config/directory-excludes.cfg`, v11 `--exclude-path`) or a line in
`config/false_positive_filters.cfg`.

## Case sensitivity cheat sheet

```text
\\payload\.exe;80            # plain (all escaped)     -> matches \PAYLOAD.EXE too
\\payload[0-9]\.exe;80       # regex                   -> case-sensitive, misses \PAYLOAD1.EXE
(?i)\\payload[0-9]\.exe;80   # regex with (?i)         -> case-insensitive
```

## Time-based anomalies are not filename IOCs

Use a meta YARA rule (sees every file and its externals), file `case2611-meta.yar`:
```yara
rule Case2611_New_EXE_In_System32 {
    meta:
        description = "EXE created in the last 7 days in System32"
        score = 50
    condition:
        extension == ".exe" and age < 7 and filepath matches /\\windows\\system32$/i
}
```

## THOR 11 YAML alternative (`case2611.yml`)

```yaml
title: Case 2611 file names
iocs:
  files:
    - value: \mimikatz.exe          # plain, case-insensitive substring
      score: 100
    - value: '(?i)\\Temp\\[^\\]+\.exe'
      type: regex
      score: 50
      false_positives:
        - value: \Temp\setup
```

## Verify

```bash
./thor-linux-64 --list-signatures | grep -i mimikatz     # THOR 11; THOR 10: --print-signatures
```
Startup: `Reading iocs from …case2611-filename-iocs.txt as 'filename' type` and
`Successfully compiled N filename ioc strings and M filename ioc regexs`. Filename IOCs need no deep scan, so a
quick `--path` test on a folder containing a file with the matching name is enough.
