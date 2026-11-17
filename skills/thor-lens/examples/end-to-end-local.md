# Example: live host → audit trail → Lens → AI client

Scenario: a suspicious Linux web server `web01`. THOR 11 (full edition, normal Server
license) runs on `web01`; Lens runs on the analyst workstation.

## 1. Scan with an audit trail (on web01)

```bash
cd /opt/thor                      # THOR 11 program folder
sudo ./thor-util update           # current signatures (see the thor-maintenance skill)
sudo ./thor-linux-64 --audit-trail -e /var/tmp/thor-web01
```

- No `--lab`: on a live host it would drop every module except Filescan (and needs a Lab
  license). The audit trail needs no special license.
- Output in `/var/tmp/thor-web01/`: `web01_thor_<time>.jsonl` (findings), `.html`,
  `web01_files_md5s.csv`, `web01_thor_audit_<time>.jsonl.zst` (audit trail).
- Windows equivalent (elevated): `thor64.exe --audit-trail -e C:\thor-results`.
- THOR 10.7 or Lite instead? Use the JSON log (`--jsonfile=… --jsonv2` on 10.7, default `.jsonl`
  on Lite 11): findings-only timeline.

Copy the folder to the workstation (`scp -r web01:/var/tmp/thor-web01 /cases/`).

## 2. Check the file (workstation)

```bash
scripts/validate_audit_trail.sh /cases/thor-web01/web01_thor_audit_2026-11-16_1004.jsonl.zst
# Format: THOR 11 audit trail ...  Host: web01  RESULT: importable
```

## 3. Import both files into one case

```bash
cd /opt/thor-lens
./thorlens import \
  --log /cases/thor-web01/web01_thor_audit_2026-11-16_1004.jsonl.zst \
  --case web01
jq '{source_format, source_records, timeline_rows, min_ts, max_ts, hostnames}' cases/web01/meta.json
```

The audit trail already contains every assessment of the JSON log (plus clean elements), so
importing the `.jsonl` as well would duplicate findings. Import the JSON log alone only when
no audit trail exists.

## 4. Serve and explore

```bash
./thorlens serve --case ./cases/web01
```

Open http://127.0.0.1:8080:

1. Histogram → score mode; brush the period around the first high-score bar.
2. Filter "detections only", sort by score; open the top event; follow **References**
   (parent archive, process image, service binary).
3. Tag (`t`) and bookmark (`b`) relevant events; `Shift+F` hides noisy entities
   (confirmation shows how many rows).
4. Case view → *Actionable* / *Needs review*; export CSV or HTML for the report.

## 5. Connect Claude Code (optional)

```bash
claude mcp add --transport http --scope project thor-lens http://127.0.0.1:8080/mcp
```

Example prompts: "Call get_case_info and summarize scope", "List events with score ≥ 70 and
group them by rule", "For the top event, show related events within 30 minutes",
"Tag the confirmed web shell events `web-shell` and add a comment with the reason".

## 6. Wrap up

- Close the case in the UI (case-name menu → **Close case…**) or stop `serve` with Ctrl-C.
- Keep `cases/web01/` as the investigation record (Parquet + notes). Deleting the case folder
  deletes all notes; the original THOR files are separate.
- Audit trails and case folders contain host data; store them like evidence.
