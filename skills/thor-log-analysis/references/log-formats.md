# THOR output formats and field names

All examples are synthetic. Before printing raw lines from a real log, always filter them with
`grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information'`.

## Output files per version

| Output | THOR 10.7 | THOR 11 |
|---|---|---|
| Text log | **on**: `-l/--logfile`, default `:hostname:_thor_:time:.txt`, `--nolog` disables text and HTML | **off**: only with `-l/--text <file>` |
| JSON log | **off**: `--jsonfile[=FILE]` (default `:hostname:_thor_:time:.json`), schema v1, v2 with `--jsonv2` | **on**: `--json FILE` (value required), default `<hostname>_thor_<time>.jsonl`, schema v3. `--jsonv2` is a no-op. `--no-json` also disables HTML |
| HTML report | **on**, built from the text log at the end of the scan. Not written with `--nohtml`, `--nolog`, `--encrypt`, or on a non-zero exit | **on**, built from the JSON log. Not written with `--no-html`, `--no-json`, `--encryption-key`, or on a non-zero exit |
| Hash list CSV `md5,path,score` (no header) | **on**: `-o/--csvfile`, `:hostname:_files_md5s.csv`, Filescan hits >= `--min`, overwritten each run | **on**: `-o/--csv`, `<hostname>_files_md5s.csv`, file objects >= `--min` |
| Stats CSV `host,start,end,version,cmdline,alerts,warnings,notices,errors` | `--stats-file[=FILE]` | `--stats-csv[=FILE]` |
| Audit trail | `--audit-trail=FILE` (experimental, gzip JSON, no default name) | `--audit-trail[=FILE]`, default `<hostname>_thor_audit_<time>.jsonl.zst` (zstd) |
| Output directory | `-e/--rebase-dir` (only for names without a path separator) | `-e/--output-directory` |
| Placeholders | `:hostname:`, `:time:` | `<hostname>`, `<time>` |

There are also syslog/SIEM sinks (`-s/--syslog` in v10, `-s/--remote-log` in v11, formats DEFAULT, CEF,
JSON, SYSLOGJSON, SYSLOGKV), `--local-syslog` and `--eventlog`. In v11, a JSON remote-log target
receives v3 objects.

## Text log (v10 default, v11 `--text`)

```
Nov 16 09:14:02 WKS-042/10.20.30.42 THOR: Alert: MODULE: Filescan MESSAGE: Malware file found SCANID: S-pV3sTq9xYk0 SCORE: 91 FILE: C:\Users\Public\Libraries\svchost.exe EXT: .exe TYPE: EXE SIZE: 73802 MD5: a3f1... SHA1: 0b1c... SHA256: 9e8d... FIRSTBYTES: 4d5a9000... / MZ CREATED: Sun Nov 15 22:10:03.123 2026 MODIFIED: Sun Nov 15 22:10:03.123 2026 OWNER: BUILTIN\Administrators REASON_1: YARA rule HKTL_Example_Strings / Detects tool command strings SUBSCORE_1: 85 REF_1: https://example.org SIGTYPE_1: internal SIGCLASS_1: YARA Rule MATCHED_1: Str1: sekurlsa::logonpasswords at 0x4a2f0 RULEDATE_1: 2026-11-01 TAGS_1: HKTL, T1003 RULENAME_1: HKTL_Example_Strings AUTHOR_1: Example Author REASON_2: Executable in suspicious location SUBSCORE_2: 60 ... REASONS_COUNT: 3
Nov 16 10:02:05 WKS-042/10.20.30.42 THOR: Info: MODULE: Report MESSAGE: Results SCANID: S-pV3sTq9xYk0 ALERTS: 1 WARNINGS: 2 NOTICES: 1 ERRORS: 0
```

- Header: `<Mmm _d HH:MM:SS> <hostname>/<first IP> THOR: <Level>: `. The line timestamp is UTC and has no
  year. Embedded times are ANSI C, in local time unless `--utc` (v10) / `--timestamp-utc` (v11).
  `--rfc3339` / `--timestamp-rfc3339` changes the layout only.
- Keys are UPPERCASE `KEY: value`. A value is Go-quoted (`"..."`) when it contains a `WORD: ` token,
  starts with `"` or contains a newline. Values are truncated at `--truncate` (default 2048) with `[...]`.
  Duplicate keys get `_2`, `_3`.
- Key/value variant (`--keyval` v10, `--key-value` v11): `MODULE='Filescan' MESSAGE='...' FILE='C:\\x'`
  (single quotes; `'` and `\` escaped).
- **v10** field order: MODULE, MESSAGE, SCANID, then module fields. SCORE appears wherever the module
  put it, or at the end. **v11** text is rendered from the v3 object: MODULE, MESSAGE, SCANID, SCORE,
  subject fields, REASON_N block, REASONS_COUNT, PARENT_*/ORIGIN_* (archive parent and topmost container).
- End of scan: **v10** `MODULE: Report MESSAGE: Results ALERTS: n WARNINGS: n NOTICES: n ERRORS: n`.
  **v11** `MESSAGE: Assessments` (alerts/warnings/notices/infos) and `MESSAGE: Messages` (errors ...).
  If these lines are missing, the scan did not finish.
- Console output is not the log format: no header, and it has line breaks before FILE/MD5/REASON keys.

## Reason fields across formats

| Text (both) | v10 JSON v1 | v10 JSON v2 `reasons[]` | v11 JSON v3 `reasons[]` |
|---|---|---|---|
| REASON_N | `reason_N` | `name` | `summary` |
| SUBSCORE_N | `subscore_N` | `score` | `signature.score` |
| RULENAME_N (v10: YARA only; v11: YARA, Sigma title, IOC) | `rulename_N` | `signature.rulename` | `signature.rule_name` |
| SIGCLASS_N | `sigclass_N` | `sigclass` | `signature.kind` |
| SIGTYPE_N (`internal`/`custom`/`external`) | `sigtype_N` | `sigtype` | `signature.origin` |
| REF_N | `ref_N` | `signature.ref` | `signature.reference[]` |
| TAGS_N | `tags_N` (string) | `signature.tags[]` | `signature.tags[]` |
| RULEDATE_N | `ruledate_N` | `signature.ruledate` | `signature.date` |
| AUTHOR_N, DESCRIPTION_N, ID_N (Sigma), FALSEPOSITIVES_N | `author_N`, ... | `signature.author`, ... | `signature.author`, `.description`, `.id`, `.false_positives[]` |
| MATCHED_N | `matched_N` (array) | `matched` | `matched[] {data:{data,encoding}, offset, field, context}` |
| REASONS_COUNT | `reasons_count` | none | `reason_count` |

- SIGCLASS values: YARA Rule, Sigma Rule, Filename IOC, Hash IOC, Keyword IOC, Named Pipe IOC, STIX IOC,
  Internal Heuristic. v11 adds Domain IOC and Handle IOC.
- REASON text: YARA `YARA rule <name> / <description>` (both). Sigma is `<title>` in v10 and `Sigma rule <title>`
  in v11. v11 IOCs read `<Class> <ioc>`, e.g. `Hash IOC ...`.
- `AUTHOR_N: unknown` together with `REF_N: not set` indicates a YARA rule without metadata, which is typical for custom or third-party rules.
- MATCHED: v10 `Str1: <data> [in <context>] [at 0xOFF] [in <field>] Str2: ...`, `(none)` if empty. v11
  prints a single match without `Str1:`. v11 JSON `encoding: hex` means hex-encoded data (`xxd -r -p`).

## v10 JSON v1 and v2

```
{"time":"2026-11-16T09:14:02Z","hostname":"WKS-042","level":"Alert","module":"Filescan","message":"Malware file found","scanid":"S-...","score":91,"file":"C:\\Users\\Public\\Libraries\\svchost.exe","md5":"a3f1...","reason_1":"YARA rule HKTL_Example_Strings / ...","subscore_1":85,"rulename_1":"HKTL_Example_Strings","sigclass_1":"YARA Rule","sigtype_1":"internal","reasons_count":3,"log_version":"v1.0.0"}
{"time":"...","hostname":"WKS-042","level":"Alert","module":"Filescan","message":"Malware file found","score":91,"file":{"path":"C:\\...\\svchost.exe","md5":"a3f1...","size":73802},"reasons":[{"name":"YARA rule HKTL_Example_Strings / ...","score":85,"signature":{"rulename":"HKTL_Example_Strings","tags":["HKTL","T1003"]},"matched":[{"data":"sekurlsa::logonpasswords","offset":303856}],"sigtype":"internal","sigclass":"YARA Rule"}],"log_version":"v2.0.0"}
```

- Top-level keys: `time` (UTC, time of writing), `hostname`, `level`, `module`, `message`, the lowercase
  module keys, and `log_version` last.
- There is no type field. Findings are records with `score`. Messages lack it, and some v10 findings do too.

```bash
# findings sorted by score (v1 and v2)
jq -r 'select(.score != null) | [.level, .score, .hostname, .module,
  (.file.path? // .file // .image_file // .event_channel // "-"),
  (.rulename_1 // .reason_1 // (.reasons[0]? | (.signature.rulename // .name)) // "-")]
  | map(tostring) | join("\t")' thor.json | sort -t$'\t' -k2,2nr
# reason histogram (v1)
jq -r 'select(.score != null) | to_entries[] | select(.key|test("^reason_[0-9]+$")) | .value' thor.json | sort | uniq -c | sort -rn
# level counts of findings
jq -s -c 'map(select(.score != null)) | group_by(.level) | map({(.[0].level): length}) | add' thor.json
```

## v11 JSON v3 (`.jsonl`, default)

```
{"type":"THOR message","meta":{"time":"2026-11-16T10:13:51.2077+01:00","level":"Info","module":"Startup","scan_id":"S-...","hostname":"WKS-042"},"message":"Thor Version: 11.0.0","fields":{},"log_version":"v3.0.0"}
{"type":"THOR assessment","meta":{"time":"2026-11-16T10:14:02.4180+01:00","level":"Alert","module":"Filescan","scan_id":"S-...","hostname":"WKS-042"},"message":"Malicious file found","score":91,"subject":{"type":"file","path":"C:\\Users\\Public\\Libraries\\svchost.exe","exists":"yes","extension":".exe","magic_header":"EXE","hashes":{"md5":"a3f1...","sha1":"0b1c...","sha256":"9e8d..."},"first_bytes":{"hex":"4d5a9000...","ascii":"MZ"},"file_times":{"modified":"...","created":"..."},"size":73802},"reasons":[{"type":"reason","summary":"YARA rule HKTL_Example_Strings / ...","signature":{"score":85,"reference":["https://example.org"],"origin":"internal","kind":"YARA Rule","rule_name":"HKTL_Example_Strings","tags":["HKTL","T1003"]},"matched":[{"data":{"data":"sekurlsa::logonpasswords","encoding":"plain"},"offset":303856}]}],"reason_count":3,"ancestors":null,"derivatives":null,"issues":[{"affected":"/reasons","category":"truncated","description":"Limited to 2 reasons"}],"log_version":"v3.0.0"}
{"type":"THOR message","meta":{...,"module":"Report"},"message":"Assessments","fields":{"assessments":{"alerts":1,"warnings":1,"notices":0,"infos":42}},"log_version":"v3.0.0"}
```

- `type`: `THOR assessment` (an assessed object at any level), `THOR message` (status, errors, counters,
  at any level including Warning/Error). The `THOR message` "Scan Information" carries an object of
  type `THOR invocation information` in `fields.object` (scan parameters, including `license.owner`: do not print). Early THOR 11 tech-preview builds wrote `THOR finding` with `context[]`
  instead of `ancestors`/`derivatives`.
- `meta`: `time` (RFC3339 with nanoseconds and offset), `level`, `module`, `scan_id`, `event_id` (only with
  `--log-message-ids`), `hostname`. Assessment: `message`, `score`, `subject`, `reasons`, `reason_count`,
  `ancestors[] {per, distance, top_level, object}` (archive chain: parent = distance 1),
  `derivatives[] {via, object}` (files referenced by the subject), `issues[]` (truncations).
- `subject.type` values include: `file`, `process`, `eventlog entry`, `registry key`, `registry value`,
  `Windows service`, `systemd service`, `init.d service`, `autorun entry`, `scheduled task`,
  `registry scheduled task`, `AmCache entry`, `shim cache entry`, `log line`, `named pipe`, `mutex`/`event`,
  `cron job`, `DNS cache entry`, `firewall rule`, `Linux kernel module`, `eBPF program`, `MFT entry`.
  Run `--describe-object-type all` to get the full list with fields.
- Main identifiers: file `path`; process `pid`, `name`, `command`, `owner`, `image.path`,
  `parent_info.{pid,exe,command}`; eventlog entry `channel`, `event_id`, `entry{...}`; registry `key`;
  Windows service `service_name`, `image.path`; autorun `location`, `entry`, `launch_string`; log line
  `line`, `line_index`, with the log file in `ancestors`.
- `matched[].field` is a JSON pointer into the subject (e.g. `/entry/CommandLine`).
- End of scan: messages `Assessments` (`fields.assessments`) and `Messages` (`fields.messages.errors`).

More jq examples:

```bash
J='select(.type=="THOR assessment" or .type=="THOR finding")'
jq -r "$J | select(.meta.level!=\"Info\") | .subject.type" f.jsonl | sort | uniq -c | sort -rn
jq -r "$J | select(.subject.type==\"process\" and .meta.level!=\"Info\")
  | [.score, .subject.pid, .subject.image.path, .subject.command] | map(tostring) | join(\"\t\")" f.jsonl
jq -r "$J | .reasons[]? | .matched[]? | [.data.encoding, .data.data, (.offset // \"-\"), (.field // \"-\")]
  | map(tostring) | join(\"\t\")" f.jsonl
jq -r "$J | select(.meta.level==\"Alert\") | .subject.hashes.sha256 // empty" f.jsonl | sort -u   # for lookups
```

## Converting and rendering

| Task | Command (both versions) |
|---|---|
| JSON -> text log | `thor-util logconvert -f in.jsonl -o out.txt --from-json --to-log` |
| text -> JSON (v1 shape) | `thor-util logconvert -f in.txt -o out.json --from-log --to-json` |
| -> CSV / one CSV per module in a ZIP | `--to-csv` / `--to-csv-zip` (also `--to-kv`; `--from-kv` is not implemented) |
| HTML report from one or more logs | `thor-util report --logfile a.txt [--logfile b.jsonl]` or `--logdir <dir>` (one `.htm` per log file, despite the help text), `--outfile`, `--filter <regex file>` |
| Decrypt encrypted logs | `thor-util decrypt [--privkey <key or file>] <files>`. v10 `--encrypt` without `--pubkey` uses the built-in key. v11 always uses the key given in `--encryption-key` |

`thor-util report` reads `.txt`, `.log`, `.json` and `.jsonl`. Its `--include-info` option is parsed but
has no effect. See the `thor-maintenance` skill for thor-util details.

## Audit trail

| | THOR 10.7 (experimental) | THOR 11 |
|---|---|---|
| Flag | `--audit-trail=FILE` (value required, no placeholders, not moved by `-e`) | `--audit-trail[=FILE]`, default `<hostname>_thor_audit_<time>.jsonl.zst` |
| Compression | gzip, always | zstd, always (whatever the file name). Encrypted after compression with `--encryption-key` |
| Records | `{"info":{Name,Timestamps,Id,Details},"findings":[{Level,Message,Module,...}],"references":[...]}` | `{"type":"THOR audit record","id","object":{type,...},"timestamps","reasons","references":[{target_id,relation:"child of"/"points to"}]}` and `{"type":"THOR audit message","time","level","module","message","fields"}` |
| Content | elements from modules that report element info; findings are Alert/Warning/Notice only | all scanned elements, including clean ones (log lines, event and registry entries only when relevant). Reasons with score <= 0 are omitted, there is no total score, and `--min` and `--log-size-limit` do not apply |
| Tool | none (Lens cannot import it) | THOR Lens (`thor-lens` skill) |

The first records of a v11 audit trail are startup messages, including `License file found`. Never use
`head` on a raw audit trail:

```bash
zstd -dc host_thor_audit_*.jsonl.zst | jq -c 'select(.type=="THOR audit record" and ((.reasons // []) | length) > 0)' | head
gzip -dc v10-audit.json.gz | jq -c 'select((.findings // []) | length > 0)' | head
```

THOR Lens also imports standard JSON logs (v1/v2/v3), which give a findings-only timeline. For all
elements and relations, use the v11 audit trail.
