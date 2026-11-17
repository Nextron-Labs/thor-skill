#!/bin/sh
# validate_audit_trail.sh - check a THOR log file before importing it into THOR Lens.
#
# Detects compression by content (zstd, gzip, plain), tests integrity, classifies the
# format (THOR 11 audit trail, THOR JSON log v1/v2/v3, THOR 10 audit trail, text log)
# and prints host, THOR version and scan ID from the startup messages.
#
# Privacy: never prints raw log lines or message texts. License data ("License file found",
# LICENSE_OWNER, and license.owner inside the v11 "Scan Information" message) never reaches
# the output: from "Scan Information" only the scan_id field is extracted.
#
# Requires: jq; zstd for .zst input; gzip for .gz input. POSIX sh.
# Exit codes: 0 importable, 1 usage/IO error, 2 corrupt compression,
#             3 not importable (unknown/text/THOR 10 audit trail/invalid JSON).

set -u

usage() {
    cat <<'EOF'
Usage: validate_audit_trail.sh [options] FILE

Checks a THOR audit trail (.jsonl.zst) or THOR JSON log (.jsonl/.json, .gz, .zst)
before `thorlens import`. Read-only.

Options:
  -n N           classify the first N lines (default 200)
  --full         count record types over the whole file (slow on large files)
  --no-integrity skip the full decompression test
  -h, --help     show this help

Exit codes: 0 importable, 1 usage/IO error, 2 corrupt compression,
            3 not importable by THOR Lens
EOF
}

N=200
FULL=0
INTEGRITY=1
FILE=""
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -n) [ $# -ge 2 ] || { echo "ERROR: -n needs a value" >&2; exit 1; }
            N=$2; shift ;;
        --full) FULL=1 ;;
        --no-integrity) INTEGRITY=0 ;;
        -*) echo "ERROR: unknown option: $1" >&2; usage >&2; exit 1 ;;
        *) [ -z "$FILE" ] || { echo "ERROR: only one FILE allowed" >&2; exit 1; }
           FILE=$1 ;;
    esac
    shift
done

[ -n "$FILE" ] || { usage >&2; exit 1; }
case "$N" in ''|*[!0-9]*) echo "ERROR: -n must be a positive integer" >&2; exit 1 ;; esac
[ "$N" -gt 0 ] || { echo "ERROR: -n must be > 0" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found in PATH" >&2; exit 1; }
[ -f "$FILE" ] || { echo "ERROR: not a regular file: $FILE" >&2; exit 1; }
[ -r "$FILE" ] || { echo "ERROR: file not readable: $FILE" >&2; exit 1; }
[ -s "$FILE" ] || { echo "ERROR: file is empty: $FILE" >&2; exit 1; }

SIZE=$(wc -c < "$FILE" | tr -d ' ')
MAGIC=$(od -An -tx1 -N4 "$FILE" | tr -d ' \n')
case "$MAGIC" in
    28b52ffd) COMP=zstd ;;
    1f8b*)    COMP=gzip ;;
    *)        COMP=none ;;
esac

case "$COMP" in
    zstd) command -v zstd >/dev/null 2>&1 || { echo "ERROR: zstd not found (needed for zstd content)" >&2; exit 1; }
          cat_file() { zstd -dcq -- "$FILE"; } ;;
    gzip) command -v gzip >/dev/null 2>&1 || { echo "ERROR: gzip not found" >&2; exit 1; }
          cat_file() { gzip -dc -- "$FILE"; } ;;
    none) cat_file() { cat -- "$FILE"; } ;;
esac

echo "File:        $FILE"
echo "Size:        $SIZE bytes"
echo "Compression: $COMP (detected by content)"
case "$FILE:$COMP" in
    *.zst:none|*.zstd:none|*.gz:none)
        echo "WARNING: name has a compression suffix but content is plain; THOR Lens rejects this - rename it" ;;
esac

if [ "$INTEGRITY" -eq 1 ] && [ "$COMP" != none ]; then
    if [ "$COMP" = zstd ]; then zstd -tq -- "$FILE" 2>/dev/null; RC=$?
    else gzip -t -- "$FILE" 2>/dev/null; RC=$?; fi
    if [ $RC -ne 0 ]; then
        echo "Integrity:   FAILED (truncated or corrupt - was the scan still running or the copy incomplete?)"
        exit 2
    fi
    echo "Integrity:   OK"
fi

# Classify the first N lines. jq -R reads raw lines so invalid JSON does not abort.
# Only type names and a few whitelisted fields are extracted - never message text,
# except the THOR version string.
SUMMARY=$(cat_file 2>/dev/null | head -n "$N" | jq -R -s -r '
  def kind:
    if (. | length) == 0 then "blank"
    else (try fromjson catch null) as $j
    | if $j == null or ($j|type) != "object" then "notjson"
      elif $j.type == "THOR audit record" or $j.type == "THOR audit message" then $j.type
      elif $j.type == "THOR assessment" or $j.type == "THOR message" or $j.type == "THOR finding" then "v3:" + $j.type
      elif ($j|has("info")) and ($j|has("findings")) then "v10audit"
      elif (($j.log_version // "") | startswith("v1")) then "v1"
      elif (($j.log_version // "") | startswith("v2")) then "v2"
      elif ($j|has("module")) and ($j|has("level")) then "v1"
      elif ($j|has("id")) and ($j|has("object")) then "legacyaudit"
      else "otherjson" end
    end;
  (split("\n") | map(select(length > 0))) as $lines
  | ($lines | map(kind)) as $k
  | ($lines | map(try fromjson catch null) | map(select(. != null and type == "object"))) as $objs
  | "COUNTS " + ($k | group_by(.) | map("\(.[0])=\(length)") | join(" ")),
    "VERSION " + ([ $objs[] | select(.type == "THOR audit message" and ((.message // "") | startswith("Thor Version:"))) | .message | sub("^Thor Version: *"; "") ] + [ $objs[] | select(.type == "THOR message" and ((.message // "") | startswith("Thor Version:"))) | .message | sub("^Thor Version: *"; "") ] | first // ""),
    "HOST " + ([ $objs[] | select(.type == "THOR audit message" and .message == "System Information") | .fields.object.hostname // empty ] + [ $objs[] | .meta.hostname? // empty ] + [ $objs[] | select(has("hostname")) | .hostname | strings ] | first // ""),
    "SCANID " + ([ $objs[] | select(.type == "THOR audit message" and .message == "Scan Information") | .fields.object.scan_id // empty ] + [ $objs[] | .meta.scan_id? // empty ] + [ $objs[] | .scanid? // empty | strings ] | first // ""),
    "LOGVER " + ([ $objs[] | .log_version? // empty | strings ] | unique | join(","))
' 2>/dev/null)

if [ -z "$SUMMARY" ]; then
    echo "ERROR: could not read any lines (binary or unreadable content?)"
    exit 3
fi

COUNTS=$(printf '%s\n' "$SUMMARY" | sed -n 's/^COUNTS //p')
VERSION=$(printf '%s\n' "$SUMMARY" | sed -n 's/^VERSION //p')
HOST=$(printf '%s\n' "$SUMMARY" | sed -n 's/^HOST //p')
SCANID=$(printf '%s\n' "$SUMMARY" | sed -n 's/^SCANID //p')
LOGVER=$(printf '%s\n' "$SUMMARY" | sed -n 's/^LOGVER //p')

echo "First $N lines: $COUNTS"

has() { case " $COUNTS " in *" $1="*) return 0 ;; *) return 1 ;; esac; }

VERDICT=""; RC=0
if has "THOR audit record" || has "THOR audit message"; then
    VERDICT="THOR 11 audit trail (full timeline: all assessed elements + references)"
elif has "v3:THOR assessment" || has "v3:THOR message" || has "v3:THOR finding"; then
    VERDICT="THOR JSON log v3 (THOR 11; findings at or above --min, no clean elements)"
elif has v2; then
    VERDICT="THOR JSON log v2 (THOR 10 --jsonv2; findings only)"
elif has v1; then
    VERDICT="THOR JSON log v1 (THOR 10 default JSON; findings only)"
elif has legacyaudit; then
    VERDICT="legacy audit trail without type envelope (early THOR 11 builds; importable)"
elif has v10audit; then
    VERDICT="THOR 10 audit trail (info/findings schema) - NOT importable by THOR Lens"; RC=3
elif has notjson; then
    VERDICT="not JSON (THOR text log, HTML or CSV?) - NOT importable; use the .jsonl/.json output"; RC=3
else
    VERDICT="unknown JSON - THOR Lens will likely fail with 'no THOR records found'"; RC=3
fi
echo "Format:      $VERDICT"
[ -n "$LOGVER" ]  && echo "log_version: $LOGVER"
[ -n "$VERSION" ] && echo "THOR:        $VERSION"
[ -n "$HOST" ]    && echo "Host:        $HOST"
[ -n "$SCANID" ]  && echo "Scan ID:     $SCANID"
if has notjson && [ $RC -eq 0 ]; then
    echo "NOTE: some lines are not JSON; THOR Lens keeps them as unparsed records"
fi

if [ "$FULL" -eq 1 ]; then
    echo "Counting record types over the whole file ..."
    cat_file 2>/dev/null | jq -R -r '(try fromjson catch null) as $j | if $j == null then "invalid/blank" else ($j.type // ($j.level // "untyped")) end' \
        | sort | uniq -c | sort -rn | sed 's/^/  /'
else
    LINES=$(cat_file 2>/dev/null | wc -l | tr -d ' ')
    echo "Lines:       $LINES"
fi

if [ $RC -eq 0 ]; then
    echo "RESULT: importable -> thorlens import --log \"$FILE\" --case <name>"
else
    echo "RESULT: not importable by THOR Lens"
fi
exit $RC
