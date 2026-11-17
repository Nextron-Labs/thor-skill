#!/bin/sh
# case_inventory.sh - read-only summary of a THOR Lens case directory.
#
# Reads meta.json (timeline_rows, source_records, min_ts/max_ts, object_type_counts,
# hostnames, ingestion state), the Parquet layout (events/month=YYYY-MM-01/ for imports,
# events/batches/<batch>/month=.../ for network-received cases), import diagnostics and,
# if sqlite3 is installed, annotation/agent counts.
#
# Never writes: SQLite databases are opened with ?immutable=1 (no lock, no -wal/-shm
# changes). Consequence: notes still in the -wal file of a case that a running
# THOR Lens service has open are not counted - close the case for exact numbers.
#
# Requires: jq. Optional: sqlite3. POSIX sh.
# Exit codes: 0 ok, 1 usage error or not a case directory.

set -u

usage() {
    cat <<'EOF'
Usage: case_inventory.sh [-h] CASE_DIR

Read-only inventory of a THOR Lens case, e.g. ./cases/investigation1
(the directory that contains meta.json and events/).

Prints: case metadata from meta.json, time range, top object types, hosts,
Parquet partitions and size, import diagnostics, annotation and agent-run counts.
EOF
}

case "${1:-}" in
    -h|--help) usage; exit 0 ;;
    '') usage >&2; exit 1 ;;
esac
[ $# -eq 1 ] || { echo "ERROR: exactly one CASE_DIR expected" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found in PATH" >&2; exit 1; }

CASE_DIR=${1%/}
META="$CASE_DIR/meta.json"
[ -d "$CASE_DIR" ] || { echo "ERROR: not a directory: $CASE_DIR" >&2; exit 1; }
if [ ! -f "$META" ]; then
    echo "ERROR: $META not found - not a THOR Lens case directory." >&2
    echo "       serve/inventory take the case PATH (./cases/<name>), import takes the case NAME." >&2
    exit 1
fi
jq -e 'type == "object"' "$META" >/dev/null 2>&1 || { echo "ERROR: meta.json is not valid JSON" >&2; exit 1; }

echo "THOR Lens case: $CASE_DIR"
echo "================================================================"
jq -r '
  def n: if . == null then "-" else tostring end;
  "Case name:        \(.case_name | n)",
  "Source format:    \(.source_format | n)   (audit_trail = full timeline, thor_log = findings only)",
  "Imported:         \(.import_time | n) with THOR Lens \(.tool_version | n)",
  "Source files:     \((.source_files // [.source_file] | map(select(. != null and . != "")) | length))",
  "  source_file:    \(.source_file | n | if length > 160 then .[0:160] + " ..." else . end)",
  "Hosts:            \((.hostnames // []) | if length == 0 then "- (not recorded)" elif length > 10 then "\(length) hosts: \(.[0:10] | join(", ")), ..." else join(", ") end)",
  "Source records:   \(.source_records | n)",
  "Timeline rows:    \(.timeline_rows | n)   (one record expands to one row per timestamp)",
  "Untimed rows:     \(.untimed_rows // 0 | n)   observation-only: \(.observation_only_rows // 0 | n)",
  "Time range:       \(.min_ts | n) .. \(.max_ts | n)",
  "Parse errors:     \(.parse_errors // 0 | n)   unparsed (fallback) lines: \(.fallback_lines // 0 | n)   diagnostics: \(.import_diagnostics // 0 | n)",
  (if (.skipped_files // []) | length > 0 then "Skipped files:    \(.skipped_files | join(", "))" else empty end),
  (if .log_timezone then "Log timezone:     \(.log_timezone) (resolved: \(.log_timezone_resolved // "-"))" else empty end)
' "$META"

echo ""
echo "Top object types (timeline rows)"
echo "--------------------------------"
jq -r '(.object_type_counts // {}) | to_entries | sort_by(-.value) | .[0:12][] | "  \(.value)\t\(.key)"' "$META"

if jq -e '.ingestion != null' "$META" >/dev/null 2>&1; then
    echo ""
    echo "Ingestion"
    echo "---------"
    jq -r '.ingestion |
      "  Network received: \(.network_received)   transport: \(.transport // "-")   lifecycle: \(.lifecycle // "-")",
      "  Health: \(.health // "-")   completeness: \(.completeness // "-")   coverage: \(.coverage // "-")",
      "  Scans identified: \(.identified_scans // 0)   reported complete: \(.reported_complete_scans // 0)   population-eligible: \(.population_eligible_scans // 0)",
      "  Records: \(.records // 0)   rejected: \(.rejected // 0)   finalization: \(.finalization.status // "-")"' "$META"
fi

echo ""
echo "Parquet events"
echo "--------------"
EVENTS="$CASE_DIR/events"
if [ ! -d "$EVENTS" ]; then
    echo "  ERROR: events/ missing - case is incomplete"
else
    PQ=$(find "$EVENTS" -type f -name '*.parquet' | wc -l | tr -d ' ')
    SZ=$(du -sh "$EVENTS" 2>/dev/null | cut -f1)
    echo "  Parquet files: $PQ   size: $SZ"
    if [ -d "$EVENTS/batches" ]; then
        NB=$(find "$EVENTS/batches" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
        echo "  Layout: network-received batches ($NB batches under events/batches/<batch>/month=...)"
    fi
    MONTHS=$(find "$EVENTS" -type d -name 'month=*' | sed 's|.*/month=||' | sort -u)
    NM=$(printf '%s\n' "$MONTHS" | grep -c . || true)
    if [ "$NM" -gt 0 ]; then
        FIRST=$(printf '%s\n' "$MONTHS" | head -n 1)
        LAST=$(printf '%s\n' "$MONTHS" | tail -n 1)
        echo "  Month partitions: $NM   ($FIRST .. $LAST)"
        echo "  Note: partitions before 1990 or after next year usually come from unset/sentinel"
        echo "        dates in artifacts (1601, 1899-12-30, 1970, 1980), not from attacker activity."
    elif [ "$PQ" -gt 0 ]; then
        echo "  No month= partitions (older THOR Lens layout?)"
    fi
fi

echo ""
echo "Case files"
echo "----------"
for f in annotations.sqlite agent_status.sqlite ui_config.json import_diagnostics.jsonl .thorlens.lock; do
    if [ -e "$CASE_DIR/$f" ]; then
        extra=""
        case "$f" in
            import_diagnostics.jsonl) extra="  ($(wc -l < "$CASE_DIR/$f" | tr -d ' ') diagnostics)" ;;
            .thorlens.lock) extra="  (lock file; held only while a service has the case open)" ;;
        esac
        echo "  present  $f$extra"
    else
        echo "  absent   $f"
    fi
done
PARENT=$(dirname "$CASE_DIR"); BASE=$(basename "$CASE_DIR")
for r in "$PARENT"/.replaced-"$BASE"-*; do
    [ -d "$r" ] && echo "  kept by --replace: $r"
done

count() { # db table -> count or '-'
    sqlite3 -readonly "file:$1?immutable=1" "SELECT COUNT(*) FROM $2;" 2>/dev/null || echo "-"
}
if command -v sqlite3 >/dev/null 2>&1; then
    A="$CASE_DIR/annotations.sqlite"
    if [ -f "$A" ]; then
        echo ""
        echo "Analyst work (annotations.sqlite, read-only, WAL not read)"
        echo "-----------------------------------------------------------"
        echo "  tags: $(count "$A" tags)   comments: $(count "$A" comments)   bookmarks: $(count "$A" bookmarks)"
        echo "  selections: $(count "$A" selections)   exclusion filters: $(count "$A" exclusion_filters)"
        echo "  AI assessments: $(count "$A" ai_assessments)   case dispositions: $(count "$A" case_dispositions)"
    fi
    G="$CASE_DIR/agent_status.sqlite"
    if [ -f "$G" ]; then
        echo "  agent runs: $(count "$G" agent_runs)"
    fi
else
    echo ""
    echo "(install sqlite3 for annotation and agent-run counts)"
fi

echo ""
echo "Disk usage: $(du -sh "$CASE_DIR" 2>/dev/null | cut -f1)"
echo "Open in the UI:  thorlens serve --case \"$CASE_DIR\""
