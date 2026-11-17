# Windows live scan examples

Run in an elevated prompt (Administrator; `LOCAL_SYSTEM` via scheduled task or management tools is best).
Use `thor64.exe` (never 32-bit `thor.exe` on 64-bit Windows). Commands with only `-p -a -e -c` and shared flag names
are identical in v10 and v11; where they differ, both lines are shown.

## Standard endpoint or server sweep

```bat
thor64.exe -e C:\thor-out
```

- Default mode, all modules, system drive only. v10 writes `.txt` + `.html` + `_files_md5s.csv`;
  v11 writes `.jsonl` + `.html` + `_files_md5s.csv`.
- Expect 20 minutes to several hours. Add an AV/EDR exclusion for `thor64.exe` first (`thor-troubleshooting`).

All local disks:

```bat
v10: thor64.exe --allhds -e C:\thor-out
v11: thor64.exe --all-hard-drives -e C:\thor-out
```

## Fragile or busy production server

```bat
thor64.exe --soft -e D:\thor-out
```

- Soft: drops the heavy live checks (mutex, sessions, shares, firewall, hosts), lower priority; v10 CPU limit 70%,
  v11 50% and one thread. Do not add `--cpulimit 70 --lowprio`: soft already does that.
- Alternative that keeps all checks: `thor64.exe -c 50 -e D:\thor-out` (pauses while system CPU > 50%).

## Results to a share, JSON for a SIEM

```bat
v10: thor64.exe -e \\fs01\thor-results --utc --jsonfile=:hostname:_thor_:time:.json -s siem01:514:JSON:TCP
v11: thor64.exe -e \\fs01\thor-results --timestamp-utc -s siem01:514:JSON:TCP
```

- v10 needs `--jsonfile=` (with `=`) for JSON; v11 writes JSONL by default.
- The share must be writable for the computer account when run as SYSTEM.

## Quick triage

```bat
v10: thor64.exe --quick -e C:\thor-out
v11: thor64.exe --fast -e C:\thor-out
```

Filescan checks only files changed in the last 3 days (plus high-risk folders); no Eventlog, EVTX, log files,
firewall, profiles, hotfixes, MFT.

## Recent activity (last 7 days, all supporting modules)

```bat
v10: thor64.exe --lookback 7 --global-lookback -e C:\thor-out
v11: thor64.exe --lookback 7 --lookback-global -e C:\thor-out
```

## One suspicious folder

```bat
thor64.exe -a Filescan -p C:\Users\alice\AppData -e C:\thor-out
```

`-a Filescan` makes it a pure folder scan; without it all other modules run too. Add `--intense` (v10) / `--deep` (v11)
only if the host can take the load.

## Web server (webshell hunt)

```bat
thor64.exe -a Filescan -p C:\inetpub -p D:\webapps -e C:\thor-out
```

## Focused hunt with one keyword set

```bat
v10: thor64.exe --init-selector CobaltStrike -e C:\thor-out
v11: thor64.exe --signature-include CobaltStrike -e C:\thor-out
```

Loads only signatures whose name, tags or description contain the word. Do not use `--init-filter`/`--signature-exclude`
with broad words to "reduce false positives"; use `config\false_positive_filters.cfg`.

## Custom scan ID for an incident

```bat
thor64.exe -i IR-2026-017 -e \\fs01\thor-results
```

## Restricted test run (does not touch the real ThorDB)

```bat
v10: thor64.exe -a Filescan -p C:\thor-test --nothordb -e C:\thor-test-out
v11: thor64.exe -a Filescan -p C:\thor-test --no-thordb -e C:\thor-test-out
```

Before reading or showing the console output, filter license lines (PowerShell):
`| Select-String -NotMatch 'LICENSE_OWNER|License file found|Scan Information'`.

## Debug a missing detection on one folder

```bat
v10: thor64.exe -a Filescan -p C:\suspect --nothordb --debug --printall -e C:\thor-debug
v11: thor64.exe -a Filescan -p C:\suspect --no-thordb --debug --print-files -e C:\thor-debug
```

Same license filter as above before reading the output.

Look for "Skipping file due to file size" and "Skipping deeper file scan".

## If it fails

- Exit 1 with a license list: Workstation license on Windows Server, expired license, or a lab-gated flag.
  Check with the redacting license command in the `thor` skill.
- "unknown flag": v11 flag names on v10 (`--fast`, `--deep`, `--all-hard-drives`, `--no-thordb`, `--timestamp-utc`).
- Hangs or crawls: AV/EDR, QuickEdit mode in the console (press Enter), or permanently high system CPU (see `thor-troubleshooting`).
