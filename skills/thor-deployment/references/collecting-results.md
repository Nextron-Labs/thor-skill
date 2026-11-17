# Collecting and merging results from many hosts

## Where results come from

| Method | Results land in |
|---|---|
| Share rollout (GPO, SCCM, PsExec, Intune with share access) | results share, one set of host-named files per host |
| Ansible / SSH | fetched per host into `results/<host>/` |
| THOR Remote | `remote-logs\` on the launcher, files prefixed with the host |
| Velociraptor | uploaded to the server per flow/hunt |
| Management Center | Analysis Cockpit / MC log storage |
| THOR Cloud / Cloud Lite | campaign view in the console |
| SIEM forwarding | the SIEM (plus local files) |

Default file names per host:

| v10.7 | v11 |
|---|---|
| `HOST_thor_YYYY-MM-DD_HHMM.txt` (text, default) | `HOST_thor_YYYY-MM-DD_HHMM.jsonl` (JSON v3, default) |
| `HOST_thor_YYYY-MM-DD_HHMM.html` | `HOST_thor_YYYY-MM-DD_HHMM.html` |
| `HOST_files_md5s.csv` (no time: overwritten per run) | `HOST_files_md5s.csv` |
| `HOST_thor_….json` only with `--jsonfile` | `.txt` only with `--text` |
| `HOST_stats.csv` with `--stats-file` | `HOST_stats.csv` with `--stats-csv` |

## 1. Completeness: who finished?

```bash
cd /mnt/thor-results
# hosts that produced a log (v11; v10: *_thor_*.txt)
ls *_thor_*.jsonl | sed 's/_thor_.*//' | sort -u > scanned.txt
comm -23 <(sort -u expected-hosts.txt) scanned.txt          # never started / no access / no license
grep -L 'Thor Scan finished' *_thor_*.jsonl                  # started but not finished (v10: *.txt)
ls *_thor_*.jsonl | sed 's/\.jsonl$//' | while read -r b; do [ -e "$b.html" ] || echo "no HTML (exit != 0): $b"; done
```

- No HTML report = THOR exited with an error (timeout, resource limit, interrupt, kill).
- Host names are written as the system reports them; compare case-insensitively.
- Per-host stats lines (`--stats-csv` v11 / `--stats-file` v10): hostname, start, end, THOR
  version, command line, alert/warning/notice/error counts. `cat *_stats.csv > all-stats.csv`
  gives a fleet overview.
- Typical reasons for missing hosts: no license for that host name (look for license errors in
  its log), task not applied (GPO scope, `gpupdate`), share permissions for the computer account,
  scan lock (another THOR still running), timeout kill by the deployment tool.

## 2. Strongest findings across all hosts

v10 text logs (also v11 with `--text`):

```bash
grep -h "Alert:" /mnt/thor-results/*.txt
grep -h -e "Alert:" -e "Warning:" /mnt/thor-results/*.txt | grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information' | less -S
```

```bat
findstr /C:"Alert:" \\fs01\thor-results\*.txt
```

v11 JSON logs:

```bash
jq -r 'select(.type=="THOR assessment" and .meta.level=="Alert")
       | [.meta.hostname, .score, .meta.module, .message, (.reasons[0].signature.rule_name // .reasons[0].summary // "-")] | @tsv' *.jsonl
```

```powershell
Get-ChildItem \\fs01\thor-results\*.jsonl | ForEach-Object {
  Get-Content $_.FullName | ConvertFrom-Json |
    Where-Object { $_.type -eq 'THOR assessment' -and $_.meta.level -eq 'Alert' } |
    Select-Object @{n='host';e={$_.meta.hostname}}, score, message
}
```

v10 JSON (`--jsonfile`, v1/v2): the level is in `.level`, the host in `.hostname`:
`jq -r 'select(.level=="Alert") | [.hostname, .score, .module, .message] | @tsv' *.json`.

## 3. Rare beats common

The same finding on 100 hosts is usually admin software or a shared tool; a finding on 1–5
hosts deserves the closest look.

```bash
# v11: on how many hosts does each rule fire (Alerts + Warnings)?
jq -r 'select(.type=="THOR assessment" and (.meta.level=="Alert" or .meta.level=="Warning"))
       | [.meta.hostname, (.reasons[0].signature.rule_name // .reasons[0].summary // .message)] | @tsv' *.jsonl \
  | sort -u | cut -f2 | sort | uniq -c | sort -n | head -40
```

Then open the logs of the hosts with rare Alerts first. Interpretation of single findings:
`thor-log-analysis` skill.

## 4. Reports and tools

| Tool | Use |
|---|---|
| `thor-util report --logdir <dir>` | one self-contained HTML report per log file (text or JSON v1/v2/v3); `--logfile a,b` for selected files; `--filter <file>` drops lines matching regexes; decrypt encrypted logs first (`thor-util decrypt`) |
| `thor-util logconvert` | convert between text, key-value, JSON and CSV (e.g. one CSV for spreadsheets) |
| THOR Lens | `thorlens import --log-dir <dir> --case sweep-2026-11` → all hosts in one timeline; MCP tools `find_hosts`, `get_event_statistics` for prevalence (`thor-lens` skill). Import JSON logs (`.jsonl`/`.json`), not `.txt` |
| Analysis Cockpit | baselining and case management for large numbers of logs |
| Splunk | THOR app + add-on (Splunkbase 3717, 3718) |

## 5. Handling and retention

- Results contain host names, user names, paths, command lines and (in the log header) license
  data: restrict the share, don't upload logs to public services, filter
  `LICENSE_OWNER`/`License file found`/`Scan Information` lines before sharing excerpts.
- Keep raw logs unchanged as evidence; work on copies.
- Record wave, date, THOR and signature versions per campaign so later sweeps are comparable.
