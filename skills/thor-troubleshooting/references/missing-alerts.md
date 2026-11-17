# Missing alerts: why a known-bad element was not reported

## 1. Reproduce on the single element

```sh
# v10
./thor-linux-64 -a Filescan -p /tmp/sample --debug --printall --nothordb -e /tmp/thor-out
./thor-linux-64 -a Filescan -p /tmp/sample --debug --printall --nothordb -e /tmp/thor-out --intense
# v11
./thor-linux-64 -a Filescan -p /tmp/sample --debug --print-files --no-thordb --output-directory /tmp/thor-out --text /tmp/thor-out/debug.txt
./thor-linux-64 -a Filescan -p /tmp/sample --debug --print-files --no-thordb --output-directory /tmp/thor-out --deep
```
Pipe the console output through `| grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'` before reading or showing it.
Put the sample in its own folder so nothing else is scanned. Detected only with `--intense`/`--deep` ->
size limit or deep-scan selection (rows 1-2). Not detected at all -> signature/threshold/loading (rows 3-8).
Look for these Debug lines: `Skipping file due to file size`, `Skipping deeper file scan`,
`Skipping file due to custom exclude`, `Skipping process because it is too large`, YARA timeouts.

## 2. Causes

| # | Cause | Check | Fix |
|---|---|---|---|
| 1 | File larger than the file size limit (v10 30 MiB, v11 64 MB; 200 MB in deep/lab/all-files). Above it: no content scan, no hash, no hash IOC match; filename IOCs and meta rules still run; EVTX, hives, logs, MFT, prefetch, LNK ignore the limit | Debug `Skipping file due to file size` | v11 `--file-size-limit 100MB`; v10 `--max_file_size 100MB` (v10 `0` = 1 KiB, not unlimited; v11 `0` = unlimited). v10 start-up line `Max. file size to be scanned is ... MB` shows the effective value. Raise only on analysis hosts |
| 2 | Not selected for deep (content) scan: neither extension nor magic header looked relevant, no DEEPSCAN meta rule matched | v11 Debug `Skipping deeper file scan`; v11 `--list-deepscan-criteria` | Custom meta YARA rule tagged `DEEPSCAN` for that file type (`thor-custom-signatures` skill), or `--intense`/`--deep`, or v10 `--allfiles` / v11 `--files-all` |
| 3 | Score below the reporting threshold | Element appears only with lower `--min` | `--min` (default 40) only hides lower-scored results; check the score in a debug run |
| 4 | Sigma rule level below the threshold | Rule level `low`/`medium` | Default threshold `high` (`medium` in intense/deep): v10 `--minimum-sigma-level medium`, v11 `--sigma-threshold medium` |
| 5 | Custom signature not loaded or loaded as the wrong type | Init line `Adding rule set from <file> as '<type>' type`; v10 `--print-signatures`, v11 `--list-signatures` | File name keywords decide the type (`meta`, `keyword`, `registry`, `log`, `process`, `c2`, ...). v11 loads custom signatures only from `custom-signatures/{yara,sigma,iocs,stix}` subfolders |
| 6 | Module or feature not active | Init `Disabling module ... due to license restrictions`, soft-mode Notice, DC auto-disable (Users, Profiles, NetworkSessions, RegistryHive, LoggedIn), `--quick`/`--fast` skips Eventlog/EVTX/LogScan | Run the module explicitly (`-a`), `--no-soft`/`--nosoft` on capable hosts |
| 7 | Lookback | Info `Skipping entries that are older than ...` | Remove `--lookback`/`--fast`/`--quick` for that run |
| 8 | Excluded or filtered | Debug `Skipping file due to custom exclude`; `config/false_positive_filters.cfg` (regex on the whole log line); v10 `--init-filter`, v11 `--signature-exclude` | Narrow the regex |
| 9 | Process > size limit (2 GB, soft 500 MB) | Debug `Skipping process because it is too large` | v10 `--max_process_size`, v11 `--process-size-limit`, or `--intense`/`--deep` |
| 10 | YARA timeout (90 s) | Debug, or Error with hidden `--show-timeout` | `--yara-timeout 180` |
| 11 | Inside an archive deeper than the limits | archive depth 4, members 10000 (v10) / 100000 (v11) | v10 `--max-recursion-depth`, v11 `--archive-depth` / `--archive-file-limit` |
| 12 | License output restrictions | Trial: Notice `Trial license detected, some output will be removed`; Silent license: nothing reported; Warning `Following alert, warning, notice and debug messages are silenced due to license restrictions` | Use a production license |
| 13 | THOR Lite | Lite has fewer modules and a reduced, open signature set | Expected; see the `thor-lite` skill |
| 14 | Signatures outdated | Warning `Signature file is older than 60 days` | `thor-util update` (`thor-maintenance` skill) |

Alerts versus matches: `--max-reasons` (v10) / `--alert-reason-limit` (v11) only shortens the reason list
of a reported element; it never hides the element. Signature match limits (v10 `--max-hits` 10000,
v11 `--match-limit` 100000) stop repeated reports of the **same** rule.

## 3. Relevant extensions for deep scanning (manual list)

`.asp .vbs .ps .ps1 .rar .tmp .bas .bat .chm .cmd .com .cpl .crt .dll .exe .hta .js .lnk .msc .ocx .pcd .pif
.pot .pdf .reg .scr .sct .sys .url .vb .vbe .wsc .wsf .wsh .ct .t .input .war .jsp .php .aspx .doc .docx .xls
.xlsx .ppt .pptx .log .dump .pwd .w .txt .conf .cfg .config .psd1 .psm1 .ps1xml .clixml .psc1 .pssc .pl .www
.rdp .jar .docm .ace .job .temp .plg .asm`, plus files whose magic header is listed in
`signatures/misc/file-type-signatures.cfg`. Other files get filename/metadata checks only, unless a DEEPSCAN
meta rule or deep mode selects them.
