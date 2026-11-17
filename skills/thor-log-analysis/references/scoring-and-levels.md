# Scoring and levels (THOR 10.7 and THOR 11)

## Level thresholds

| Level | THOR 10.7 | THOR 11 |
|---|---|---|
| Alert | total >= 81 **and** highest subscore > 75 | total >= 81 **and** highest subscore >= 76 |
| Warning | total >= 60 | total >= 60 |
| Notice | total >= 40 | total >= 40 |
| below 40 but >= `--min` | Debug (printed only with `--debug`) | Info, message "Interesting <type> found" |
| below `--min` | dropped | dropped, unless the object type is logged via `--log-object`, then Info "<type> found" |
| Configurable | `--notice`, `--warning`, `--alert` (advanced flags), `-x/--min` (default 40; values <= 0 become 1) | only `-x/--min` (default 40). `--score-notice/-warning/-alert/-info` and their aliases `--notice/--warning/--alert/--info` are deprecated, hidden and **ignored** |

- An 81+ total with all subscores <= 75 is a **Warning**, and it can reach 100. Example: five reasons 70, 70, 50, 40, 40 give 84 = Warning.
- **v10:** findings logged by a direct warning or alert call carry no SCORE and are not affected by `--min`. The best-known example is SHIMCache "Found entry in suspicious directory".
- Info is not a "score 30 level". **v10** writes Info for status messages. **v11** writes Info for status
  messages, for assessments below 40 when `--min` < 40, and for every object type in the
  `--log-object` defaults (processes, services, users, autoruns, scheduled tasks, ...). A default v11
  `.jsonl` therefore contains many Info assessments. Filter them out for triage.
- `--reduced` (both versions) suppresses Info and Notice output.

## The formula

Both versions combine subscores the same way:

1. Sort subscores in descending order. Cap positive values at 100.
2. `uncertainty = Π (1 - s_i / 100 / 2^i)` over positive subscores (i = 0, 1, 2, ...), so each further reason counts half as much as the previous one.
3. Each negative subscore multiplies the uncertainty by `(1 + |s|/100)`. Any subscore <= -100 makes the total 0.
4. `total = round(100 * (1 - uncertainty))`. The result is at most 100.

| Subscores | Total | Default level |
|---|---|---|
| 75 | 75 | Warning |
| 100 | 100 | Alert |
| 75, 75 | 84 | **Warning** (no subscore >= 76) |
| 80, 40 | 84 | Alert |
| 70, 70 | 81 | **Warning** |
| 85, 60, 40 | 91 | Alert |
| 50, 40 | 60 | Warning |
| 40, 40 | 52 | Notice |
| 75, 35 (timeframe bonus) | 79 | Warning |
| 75, 30, 20 | 80 | Warning |
| 75, -50 | 63 | Warning |
| 70, -30 | 61 | Warning (not 40: scores are not summed) |
| 60, -60 | 36 | not reported |
| 100, -60 | 100 | Alert (a negative score cannot lower a 100) |
| 80, -100 | 0 | not reported |

Use `combine_scores()` in `scripts/summarize_thor_log.py` to compute other cases.

## Where subscores come from

| Source | Subscore |
|---|---|
| YARA rule without `score` meta | 75 |
| YARA rule with `score` meta | that value (-100 to 100) |
| YARA `falsepositive` meta present | score × -1. Do not combine it with a negative score, because that flips the result positive |
| Sigma rule level | low 40, medium 50, high 70, critical 100. **v11:** a custom `score:` field overrides the level |
| Hash IOC `hash` or `hash;description` | 100 |
| Hash IOC `hash;score;description` | the given score |
| Trusted / false-positive hash list | **v10:** all Filescan reasons dropped. **v11:** -100, so the total is 0 |
| Filename IOC `regex;score` | the given score (negative allowed) |
| Attacker timeframe | **v10** `-f/--epoch START -f END` (pairs, YYYY-MM-DD, end exclusive), `--epochscore` default 35. **v11** `-f/--highlight-timeframe START,END` (alias `epoch`), `--highlight-timeframe-score` default 35. Applies to files created/modified in range. Other modules use their own timeframe scores (e.g. SHIMCache 70, LNK 50) |
| Internal heuristics (location, masquerading, anomalies) | module-specific; read SUBSCORE_N and SIGCLASS_N `Internal Heuristic` |

Sigma rules below the minimum level are not loaded at all: **v10** `--minimum-sigma-level`, **v11**
`--sigma-threshold`. The default is `high`, or `medium` when the flag is left at its default and the scan
runs with `--intense`/`--lab` (v10) or `--deep`/`--lab` (v11). In v11 this also applies to custom
rules unless they set `score:`.

## Reasons shown vs counted

- Only reasons with a score > 0 are displayed, sorted by score in descending order. The default limit
  is 2: `--max-reasons` (v10) or `--alert-reason-limit` (v11, alias `max-reasons`). Set it to 0 for
  unlimited. `--allreasons` is deprecated in both versions.
- Reasons are unlimited automatically with `--intense`/`--lab` (v10) and `--deep`/`--lab` (v11).
- The count before truncation is `REASONS_COUNT` (text), `reasons_count` (v10 JSON v1) or
  `reason_count` (v11 JSON). v10 JSON v2 has no count. In v11 JSON, truncation also adds
  `issues[] {affected:"/reasons", category:"truncated"}`.
- Hidden reasons can raise the total, and hidden negative reasons can lower it. That explains a SCORE
  that does not match the visible SUBSCOREs.

## Messages by level

- **v10** Filescan picks its message from the total score: `Malware file found` (>= alert threshold),
  `Possibly Dangerous file found` (>= warning) and `Suspicious file found` (>= notice). The level also
  needs a subscore > 75, so a `Warning` that says "Malware file found" is normal. Other v10 modules
  use `Malicious|Suspicious|Notable <thing> found`. Eventlog uses `Sigma match on eventlog entry`.
- **v11** every assessment says `<Malicious|Suspicious|Noteworthy|Interesting> <object type> found`
  (Alert, Warning, Notice, Info), or plain `<object type> found` for objects logged only through
  `--log-object`.

## Priorities derived from the score

| Band | Typical content | Action |
|---|---|---|
| 95-100 with a specific rule or hash IOC | known malware, hack tool, webshell, IOC from the incident | treat as incident until disproven |
| Alert 81-94 | strong rule hit plus supporting reasons | review first |
| Warning 60-80 (or more without a >75 reason) | single default-score YARA hits, Sigma high, stacked heuristics | review next, check the spread across hosts |
| Notice 40-59 | filename IOCs, Sigma low/medium, anomalies | review in context: location, host role, timeframe |
| Info | inventory objects (v11), sub-threshold hits | only for context or timelines |

Scores of 95 or more are generally severe. A typical exception is a match on a security product's own
signature store or on an AV process's memory.

## Count caps that hide hits

| Cap | v10 | v11 | Message to look for |
|---|---|---|---|
| Per rule/IOC | `--max-hits` 10000 | `--match-limit` 100000 (alias `max-hits`), 0 = unlimited | Warning "IOC or rule reached the hit limit..." |
| Event log rule muting | Sigma rules after 10 matches; `--showall` / `--lab` lift it | live Eventlog module after 10 matches; `--show-all` / `--lab` lift it | Notice "...triggered more than 10 times. Future matches will be suppressed" |
| Per element (v10) | "Rule triggered more than N times in the current element" | - | Notice |
| Log size | reduced logging at 60 MB, exit at 64 MB (off with `--norescontrol`, `--debug`, ...) | `--log-size-limit` default 200MB, reduced logging 4 MB before | Notice "Logged more than 64 MB..." (v10) |
