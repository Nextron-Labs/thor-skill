# Analysis tools

## Nextron tools

| Tool | Use |
|---|---|
| `scripts/summarize_thor_log.py` | Multi-format, multi-host summary (text, JSON v1/v2/v3, `.gz`, `.zst`). Drops license lines |
| `thor-util report` | HTML report from one or many logs (`--logfile` repeatable, `--logdir`, `--filter <regex file>`). See the `thor-maintenance` skill |
| `thor-util logconvert` | Convert between text, key/value, JSON and CSV (`--to-csv-zip` = one CSV per module) |
| THOR Lens | Timeline UI for v11 audit trails and standard JSON logs, with an MCP server for AI-assisted triage. See the `thor-lens` skill |
| Analysis Cockpit | Central log analysis with baselining (auto-filters after the first scan, then only differences), case management and SIEM forwarding |
| Splunk | THOR APT Scanner App (Splunkbase 3717) and THOR Add-On (3718) |
| Valhalla | YARA rule info: `https://valhalla.nextron-systems.com/info/rule/<RULE_NAME>`. Shows rule metadata, past matches, previous AV verdicts, statistics and a "report false positive" button. The GUI is rate limited |
| Log Analysis Manual | `https://log-analysis-manual.nextron-systems.com/en/latest/`: example logs, common FPs, attribute evaluation |
| THOR manual | `https://thor-manual.nextron-systems.com`: output formats, scoring, flags |

## Hash and IOC lookups

| Tool | Use | Notes |
|---|---|---|
| VirusTotal | `https://www.virustotal.com/gui/file/<HASH>`, `/domain/<DOMAIN>`, `/ip-address/<IP>` | Check the detection ratio, AV names, first submission, community comments, file names, signature info and the "probably harmless" or catalogue status |
| Batch lookups | Munin (open-source batch hash lookup tool on GitHub) or your TI platform's API | Feed it hashes from the JSON log (`.subject.hashes.sha256`) or the `_files_md5s.csv` (md5,path,score) |
| MISP / OpenCTI / OTX | Correlate IOCs with known campaigns | |

Do not upload samples from customer systems to public services without permission. Hash lookups are fine,
but uploads can leak data.

Extract hashes for lookup:

```bash
# v11 JSON: SHA256 of Alerts and Warnings
jq -r 'select(.type=="THOR assessment" and (.meta.level=="Alert" or .meta.level=="Warning"))
  | .subject.hashes.sha256 // .subject.image.hashes.sha256 // empty' *.jsonl | sort -u
# v10 text: MD5 of Alerts and Warnings
grep -hE 'THOR: (Alert|Warning):' *.txt | perl -nle 'print $1 if / MD5: ([0-9a-f]{32})/' | sort -u
# any version: hash list CSV
cut -d, -f1 *_files_md5s.csv | sort -u
```

## Sample analysis

| Tool | Use |
|---|---|
| Hybrid Analysis, ANY.RUN, Joe Sandbox, CAPE | Dynamic analysis (mind the data-sharing policies) |
| PEStudio, Detect It Easy | PE imports, packer and compiler identification |
| `strings`, FLOSS | Readable and obfuscated strings |
| yara (4.x) | Re-run a specific rule against a collected file. THOR 11 uses libyara 4.5.x, not YARA-X |

## Quick workflows

**YARA hit:** rule name -> Valhalla -> read MATCHED_N / `matched[]` -> check location and PE info -> hash on VT
-> same hash or rule on other hosts?

**Sigma hit:** title, level and `FALSEPOSITIVES_N` -> the event's fields (`ENTRY` / `subject.entry`) -> timeline
around EVENT_TIME -> related process and logon events.

**Hash or filename IOC:** where did the IOC come from (`SIGTYPE_N` custom = the user's own list)? -> how
specific is the pattern? -> file present? -> execution evidence (SHIMCache/AmCache)?

**Domain/C2 IOC:** which object (DNS cache, process connection, log line) -> process and user -> passive DNS
and WHOIS history -> other hosts.

## Multi-host checklist

| Check | Good sign | Bad sign |
|---|---|---|
| Spread of a rule or hash | many hosts with a common software baseline | 1-5 hosts, same department or time window |
| Detection ratio | 0/70 | 10+/70 |
| First submission | years ago | recent or unknown |
| Signature | valid, trusted vendor | missing, invalid, odd signer |
| Sandbox | benign | network beacons, injection, persistence |
| PE compile time | old, plausible | very recent, or in the future |
