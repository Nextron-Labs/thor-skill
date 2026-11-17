---
name: thor-log-analysis
description: Triages and interprets THOR scanner output from THOR 10 (10.7) and THOR 11. Covers text logs (.txt, --text), JSON logs (--jsonfile v1/v2, THOR 11 .jsonl v3), HTML reports and the md5 hash-list CSV, from one or many systems. Use when the user pastes THOR log lines ("THOR: Alert:", MODULE:, SCORE:, REASON_1:, SUBSCORE_1:, "THOR assessment"), shares a THOR log file or a results folder, or asks what an Alert, Warning, Notice, score or reason means. Also use when the user asks whether a YARA, Sigma, filename-IOC or hash-IOC hit is a false positive, how to suppress it (false_positive_filters.cfg, trusted hashes, negative-score IOCs), or wants grep/jq recipes and a prioritized investigation plan. THOR 11 audit trails (.jsonl.zst) and timeline work belong to the thor-lens skill.
compatibility: Works on log files only. Optional tools are python3 (scripts/summarize_thor_log.py, stdlib only), jq, grep/perl and zstd (for audit trails).
metadata:
  author: Nextron Systems
  version: "2.0"
---

# THOR log analysis

Goal: turn raw THOR output into a prioritized investigation plan. THOR is tuned to avoid false
negatives, so a first scan always contains some noise. Your job is to separate it from what matters.

## Rule zero: never echo license lines

Lines with `LICENSE_OWNER` or `License file found` contain the licensee's name or e-mail. In THOR 11
JSON, the `Scan Information` message carries `license.owner` without the `LICENSE_OWNER` string.
Never print, quote or summarize these lines, even when the user asks for "the first 50 lines". Filter
every raw view:

```bash
grep -v -e LICENSE_OWNER -e 'License file found' -e 'Scan Information' FILE | head -50
```

The summary script drops these lines on its own. Before sharing logs outside the team, rescan with
`--suppresspi` (v10) or `--no-personal-data` (v11). HTML reports, logs and audit trails all contain
host data.

## 1. Identify format and version first

| What the first non-license line looks like | Format | Produced by |
|---|---|---|
| `Nov 16 09:14:02 host/10.0.0.5 THOR: Alert: MODULE: Filescan MESSAGE: ...` | text log | **v10** default `.txt`; **v11** only with `--text <file>` |
| same header, then `MODULE='Filescan' MESSAGE='...'` | key/value text | `--keyval` (v10) / `--key-value` (v11) |
| `{"time":...,"hostname":...,"level":...,"module":...,"reason_1":...,"log_version":"v1.0.0"}` | JSON v1 (flat) | **v10** `--jsonfile` |
| same, but `"file":{"path":...}`, `"reasons":[...]`, `"log_version":"v2.0.0"` | JSON v2 | **v10** `--jsonfile --jsonv2` |
| `{"type":"THOR assessment"` or `"THOR message","meta":{...}`, `"log_version":"v3.0.0"` | JSON v3 (`.jsonl`) | **v11** default output |
| `{"type":"THOR finding",...,"context":[...]}` | early v3 | THOR 11 tech preview builds before early 2026 |
| `.jsonl.zst`, records `THOR audit record` / `THOR audit message` | v11 audit trail | `--audit-trail`. Use the `thor-lens` skill |
| gzip JSON with `{"info":...,"findings":...}` | v10 audit trail (experimental) | not importable by Lens |
| `<!DOCTYPE html>` | HTML report | ask for the `.txt`/`.jsonl` it was built from |
| `md5,path,score` without a header | `<host>_files_md5s.csv` | hash list only: use it for lookups, not triage |
| `Alert Malware file found` without timestamp or host, wrapped before FILE/MD5/REASON | console output | incomplete: ask for the log file |
| binary | encrypted log | decrypt first: `thor-util decrypt` (`--privkey <key>` for v11 and custom keys) |

Get the version with `grep -m1 'Thor Version' FILE`. In JSON, use `jq -r .log_version FILE | sort -u`
(`v1.0.0`/`v2.0.0` = v10, `v3.0.0` = v11). Compressed logs: `gzip -dc` / `zstd -dc`. Field names per
format are in [log formats](references/log-formats.md).

## 2. Summarize, then slice

Run the summarizer first. It handles all formats above, plain or `.gz`/`.zst`, takes many files and
directories, and drops license lines:

```bash
python3 scripts/summarize_thor_log.py /path/to/results/            # human-readable
python3 scripts/summarize_thor_log.py --json --top 30 a.txt b.jsonl # machine-readable
```

It reports: formats and versions, whether each log has its end-of-scan summary (missing means the
scan was aborted or is still running), counts per level, host, module and object type, top
rules with host spread, top findings by score, hidden reasons, volume caps, unscored warnings, and errors.

Slice further. Run the text recipes on v10 `.txt` or v11 `--text` logs:

```bash
grep -ohE 'THOR: (Alert|Warning|Notice|Error):' *.txt | sort | uniq -c            # level counts
grep -h 'THOR: Alert:' *.txt | awk '{split($4,h,"/"); print h[1]}' | sort | uniq -c   # alerts per host
grep -hE 'THOR: (Alert|Warning|Notice):' *.txt \
  | sed -nE 's/.* REASON_1: (.*) SUBSCORE_1: ([0-9]+).*/\2\t\1/p' | sort | uniq -c | sort -rn  # top reasons
grep -hE 'THOR: (Alert|Warning):' *.txt | perl -nle 'print $1 if / FILE: (.*?) [A-Z][A-Z0-9_]*:/'  # paths
```

Run these jq recipes on v11 `.jsonl`:

```bash
J='select(.type=="THOR assessment" or .type=="THOR finding")'
jq -r "$J | .meta.level" f.jsonl | sort | uniq -c                         # incl. many Info objects
jq -r "$J | select(.meta.level==\"Alert\" or .meta.level==\"Warning\" or .meta.level==\"Notice\")
  | [.meta.level, .score, .meta.hostname, .meta.module, .subject.type,
     (.subject.path // .subject.image.path // .subject.key // .subject.channel // .subject.name // \"-\"),
     (.reasons[0].signature.rule_name // .reasons[0].summary)] | map(tostring) | join(\"\t\")" f.jsonl \
  | sort -t$'\t' -k2,2nr
jq -r "$J | select(.meta.level!=\"Info\") | .reasons[]?.signature
  | [.kind, (.rule_name // \"-\"), .score] | map(tostring) | join(\"\t\")" f.jsonl | sort | uniq -c | sort -rn
jq -c 'select(.type=="THOR message" and .meta.module=="Report") | .fields' f.jsonl   # end-of-scan counters
jq -r 'select(.type=="THOR message" and .meta.level=="Error") | [.meta.module,.message] | join("\t")' f.jsonl
```

For v10 JSON, see the recipes in [log formats](references/log-formats.md). Use `map(tostring) | join("\t")`
rather than `@tsv`, which doubles the backslashes in Windows paths.

## 3. Levels and scores

| Level | THOR 10.7 | THOR 11 |
|---|---|---|
| Alert | score >= 81 (`--alert`) **and** top subscore > 75 | score >= 81 **and** top subscore >= 76 (fixed) |
| Warning | >= 60 (`--warning`) | >= 60 (fixed) |
| Notice | >= 40 (`--notice`) | >= 40 (fixed) |
| below 40 | not logged (Debug, visible only with `--debug`, if `--min` < 40) | Info "Interesting ... found" if `--min` < 40; Info "<type> found" for `--log-object` types |
| Reporting floor | `-x/--min`, default 40 | `-x/--min`, default 40. `--notice/--warning/--alert` are deprecated and ignored |

- The score combines subscores like probabilities. It is **not additive** and is capped at 100. Subscores
  are sorted in descending order and each one counts half as much as the previous one: 75+75 -> 84, 70+70 -> 81, 75+35 -> 79.
- Consequences: an 81+ score without a reason >= 76 stays a Warning, so Warnings can reach 100. Two default
  YARA hits (75 each) make a Warning of 84. A single hash IOC (default 100) is an Alert.
- Negative subscores (FP rules or IOCs, `falsepositive` meta) lower the score multiplicatively. A
  subscore <= -100 forces 0. They are never shown, so SCORE can be lower than the visible SUBSCOREs suggest.
- Default subscores: YARA without a `score` meta = 75. Sigma low/medium/high/critical = 40/50/70/100.
  Hash IOC = 100. `--epoch` (v10) / `--highlight-timeframe` (v11) date pairs add a reason (default 35) to
  files created or modified in that range.
- Only 2 reasons are shown by default. `REASONS_COUNT` / `reason_count` gives the real number. To see
  all, rescan with `--max-reasons 0` (v10) or `--alert-reason-limit 0` (v11). `--intense`/`--lab` (v10)
  and `--deep` (v11) already show all.
- **v10** Filescan wording depends on the score alone, so `Warning: ... MESSAGE: Malware file found` is
  normal. **v11** wording follows the level: Malicious = Alert, Suspicious = Warning, Noteworthy = Notice.

For the formula, more examples, and where each subscore comes from, see [scoring and levels](references/scoring-and-levels.md).

## 4. Triage order

1. **Scan health.** Check for a missing end-of-scan summary (aborted scan), volume-cap messages ("reached
   the hit limit", "Sigma rule triggered more than 10 times" (v11: "Rule triggered …"), log size limit) and
   many Errors. Counts below a cap are incomplete.
2. **Alerts, highest score first.** Then Warnings. Notices last, and in context.
3. **Rare beats common.** A finding on 1-5 systems deserves a close look. The same finding on 100 systems
   is usually an admin tool or software everyone runs. Exceptions: a known campaign, or one IOC/hash
   that is specific to an incident. For multi-host input, count hosts per rule or hash, not lines.
4. **Custom signatures first.** `SIGTYPE_N: custom` / `signature.origin: custom` means the user's own IOCs
   or rules, which are usually high relevance.
5. Then move to module-based review (Filescan by path, ProcessCheck, persistence, event logs). See
   [module notes](references/module-notes.md).

## 5. Judge one finding

A finding record answers five questions:

| | Text (v10 / v11 `--text`) | JSON v3 (v11) |
|---|---|---|
| **Where** | `FILE`, archive members via `PARENT_*`/`ORIGIN_*` (v11) | `subject.path`, `ancestors[]` (archive chain) |
| **What** | `TYPE`, `SIZE`, `MD5`/`SHA1`/`SHA256`, `FIRSTBYTES`, PE `COMPANY`/`DESC`... | `subject.magic_header`, `hashes`, `first_bytes`, `pe_info` |
| **When / who** | `CREATED`/`MODIFIED`/`ACCESSED`, `OWNER`, `PERMISSIONS` | `file_times`, `owner`, `permissions` |
| **Why** | `REASON_N`, `SUBSCORE_N`, `RULENAME_N`, `SIGCLASS_N`, `SIGTYPE_N`, `TAGS_N`, `AUTHOR_N`, `REF_N`, `RULEDATE_N` | `reasons[].summary`, `.signature.{score,rule_name,kind,origin,tags,author,reference,date}` |
| **Evidence** | `MATCHED_N` (string, offset, context) | `reasons[].matched[]` (`data.encoding` may be `hex`) |

Ask, per finding:

1. What fired (`SIGCLASS`: YARA Rule, Sigma Rule, Hash/Filename/Keyword/Domain IOC, Internal Heuristic)
   and how specific is it? Generic, `SUSP_`/`GEN` rules and filename-only matches are weaker than
   family, APT or hash hits. Look up YARA rules at `https://valhalla.nextron-systems.com/info/rule/<RULE_NAME>`.
   For Sigma, read `FALSEPOSITIVES_N`.
2. Does the matched string prove it, or is it a description, a signature file or documentation?
3. Is the location plausible? Temp, Public, ProgramData root, web roots and the Recycle Bin are bad
   signs. A vendor folder with a valid signature is a good sign.
4. Is the file still present? SHIMCache/AmCache entries prove presence or execution even after deletion.
5. Do the timestamps match the incident window? Is the owner or user plausible (IIS/service accounts for webshells)?
6. How many hosts have it? What does VirusTotal or the sandbox say about the hash?

Use [attribute evaluation](references/attribute-evaluation.md) for weighted good/bad indicators.

## 6. False positives: classify, then suppress correctly

Common sources are admin and dual-use tools, security products (AV signature files, EDR memory),
backups and forensic copies, old THOR logs and reports, and generic packer/webshell rules on legitimate
CMS code. See [common FPs](references/common-fps.md).

| Mechanism | Effect | Use when |
|---|---|---|
| `config/false_positive_filters.cfg` | One Go regex per line, matched against the event as `KEY: value` text (`MODULE: ... MESSAGE: ... FILE: ... REASON_1: ...`). A match **drops the event completely**. v10 checks all events; v11 checks assessments only | A specific known-good finding: anchor on `MD5: <hash>` or `FILE: C:\\IT\\Tools\\nirsoft\\` plus the rule |
| Trusted hash file (name has the words `trusted`/`falsepositive` and `hashes`, e.g. `custom-signatures/iocs/my-trusted-hashes.txt`) | **v10:** a match drops all Filescan reasons. **v11:** score -100, so the total is 0 | Known-good binaries by hash |
| Negative-score filename IOC or YARA rule | Lowers the combined score. -100 suppresses | Tools that are fine in one place: `\\SysInternals\\PsExec\.exe;-60` against `\\PsExec\.exe;60` -> 36, not reported |
| Path excludes (`config/directory-excludes.cfg` v10, `--exclude-path` / `config/path-excludes.cfg` v11) | The path is **not scanned at all** | Noisy data stores, never for "this one file is fine" |
| `--init-filter` (v10) / `--signature-exclude` (v11) | Signatures matching the substring are **not loaded** on any host | Last resort: global detection loss |

Rules: keep filters narrow and commented. Never filter by rule name alone unless the rule is useless in
that environment. Remember that a negative subscore cannot pull a 100 hit below 100 unless it is <= -100.
Verify with a short test scan on a test folder, not a full scan. For file formats, see the
`thor-custom-signatures` skill.

## 7. Gotchas that change counts

- **v11** logs objects at Info by default (every process, service, user, autorun up to per-type limits).
  Triage must filter `meta.level` to Alert/Warning/Notice.
- `--reduced` (both versions) drops Info and Notice output. A scan without Notices may just be reduced.
- Match limits per rule/IOC: v10 `--max-hits` 10000, v11 `--match-limit` 100000 (Warning "reached the
  hit limit"). Event log rules are muted after 10 matches per rule (Notice "... triggered more than 10
  times"): **v10** Sigma, lifted by `--showall` or `--lab`. **v11** the live Eventlog module, lifted by
  `--show-all` or `--lab`, not by `--match-limit 0`.
- Log flood guard: **v10** switches to reduced logging at 60 MB and exits at 64 MB. **v11** uses
  `--log-size-limit`, default 200MB.
- **v10** some findings are logged without `SCORE` (e.g. SHIMCache "Found entry in suspicious directory")
  and are not affected by `--min`.
- Text line timestamps are UTC. Embedded file times are local unless `--utc` (v10) / `--timestamp-utc` (v11).
- No HTML report if THOR exited non-zero. Rebuild one with `thor-util report --logfile <log>` (see the
  `thor-maintenance` skill).

## Answer format

1. **Summary** (5-10 lines): scope (hosts, versions, scan health), the verdict and what stands out.
2. **Findings table**, sorted Alert > Warning > Notice, then by score:
   `| Host | Level | Score | Module | Subject (path/process/key) | Top reason (rule, subscore) | Assessment: likely TP / likely FP / unclear, and why |`
   For multiple hosts, add a host count per rule and group identical findings.
3. **Likely false positives**, each with the exact suppression line (FP filter regex, trusted hash, or negative IOC).
4. **Next steps** (3-7): concrete actions, such as collecting a file, looking up a hash or rule, checking a
   timeline or rescanning with all reasons. Point to `thor-lens` for timeline work when an audit trail
   exists or can be produced.

State the THOR version you assumed. If the format is ambiguous, say what you need.

## References

- [references/scoring-and-levels.md](references/scoring-and-levels.md): read when explaining a score,
  level, missing Alert, or an Info/Debug question.
- [references/log-formats.md](references/log-formats.md): read for field names per format, output files
  and flags, v10 JSON recipes, logconvert, report, decrypt and the audit trail.
- [references/module-notes.md](references/module-notes.md): read when interpreting findings from a
  specific module or object type.
- [references/common-fps.md](references/common-fps.md): read when deciding FP vs TP and writing suppressions.
- [references/attribute-evaluation.md](references/attribute-evaluation.md): read for a weighted checklist
  per attribute (path, hash, owner, PE info, timestamps).
- [references/analysis-tools.md](references/analysis-tools.md): read for external verification (VirusTotal,
  Valhalla, sandboxes) and multi-host tooling.
- [scripts/summarize_thor_log.py](scripts/summarize_thor_log.py): multi-format, multi-host summary
  (`--help`).
