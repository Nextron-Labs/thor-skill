#!/bin/sh
# quick-env-check.sh - read-only environment check for THOR troubleshooting (Linux, macOS, AIX).
# POSIX sh. Never prints process command lines, license contents or config secrets.

usage() {
    cat <<'EOF'
Usage: sh quick-env-check.sh [--no-exec] [THOR_DIR] [OUTPUT_DIR]
       sh quick-env-check.sh --help

Read-only checks that explain common THOR start/abort/slow-scan problems:
  - OS, user, root status, CPU count, total/free RAM
    (predicts THOR's automatic soft mode and the "< 50 MB free RAM" start gate)
  - free disk space for THOR_DIR, OUTPUT_DIR, the ThorDB directory and /tmp
  - Linux ulimits that THOR warns about (memlock, data, open files)
  - THOR binaries in THOR_DIR, edition, version (runs '<binary> --version' unless --no-exec)
  - signature age (> 60 days triggers a THOR warning), custom-signatures layout (v11)
  - license files: count only (contents are encrypted and never read), THOR_LICENSE set or not
  - ThorDB files at the default locations (thor10.db, thor10-lite.db, thor.db, thor-lite.db)
  - running THOR processes: PID and binary only, never command lines
  - config/thor.yml keys whose meaning changed between v10 and v11
  - macOS: Full Disk Access hint

Arguments:
  THOR_DIR    THOR program folder (default: current directory)
  OUTPUT_DIR  folder THOR writes logs to (optional; checked for free space and write access)
  --no-exec   do not run the THOR binary for --version

Exit codes: 0 = check finished (read the [WARN] lines), 2 = usage error.
Windows: not supported; use the PowerShell commands from the thor-troubleshooting skill.
EOF
}

NO_EXEC=0
THOR_DIR=""
OUT_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --no-exec) NO_EXEC=1 ;;
        -*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)
            if [ -z "$THOR_DIR" ]; then THOR_DIR=$1
            elif [ -z "$OUT_DIR" ]; then OUT_DIR=$1
            else echo "Too many arguments" >&2; usage >&2; exit 2
            fi ;;
    esac
    shift
done
[ -n "$THOR_DIR" ] || THOR_DIR=.
if [ ! -d "$THOR_DIR" ]; then
    echo "THOR_DIR does not exist or is not a directory: $THOR_DIR" >&2
    exit 2
fi

ok()   { printf '  [OK]   %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; }
info() { printf '  [INFO] %s\n' "$*"; }
section() { printf '\n--- %s ---\n' "$*"; }

OS=$(uname -s 2>/dev/null || echo unknown)
UID_NUM=$(id -u 2>/dev/null || echo 1)

# free space in MB of the filesystem holding $1 (POSIX df -P, 1K blocks)
free_mb() {
    df -Pk "$1" 2>/dev/null | awk 'NR==2 { printf "%d", $4/1024 }'
}

check_space() { # $1 label, $2 dir
    if [ ! -d "$2" ]; then
        info "$1: $2 does not exist (yet)"
        return
    fi
    fmb=$(free_mb "$2")
    if [ -z "$fmb" ]; then
        info "$1: $2 (free space unknown)"
    elif [ "$fmb" -lt 100 ]; then
        warn "$1: $2 has only ${fmb} MB free"
    else
        ok "$1: $2 has ${fmb} MB free"
    fi
    if [ -w "$2" ]; then ok "$1: writable by this user"; else warn "$1: NOT writable by this user"; fi
}

echo "=== THOR environment check (read-only) ==="

section "System"
info "OS: $(uname -s -r -m 2>/dev/null)"
info "User: $(id -un 2>/dev/null) (uid $UID_NUM)"
if [ "$UID_NUM" -eq 0 ]; then
    ok "running as root"
else
    warn "not root: THOR misses protected files/processes; v10 cannot write /var/lib/thor/thor10.db (ThorDB disabled); v11 uses a per-user ThorDB"
fi

CPUS=$(getconf _NPROCESSORS_ONLN 2>/dev/null)
[ -n "$CPUS" ] || CPUS=$(nproc 2>/dev/null)
[ -n "$CPUS" ] || CPUS=$(sysctl -n hw.ncpu 2>/dev/null)
[ -n "$CPUS" ] || CPUS=$(lsdev -Cc processor 2>/dev/null | wc -l | tr -d ' ')

TOTAL_MB=""
FREE_MB=""
case "$OS" in
    Linux)
        TOTAL_MB=$(awk '/^MemTotal:/ { printf "%d", $2/1024 }' /proc/meminfo 2>/dev/null)
        FREE_MB=$(awk '/^MemAvailable:/ { printf "%d", $2/1024 }' /proc/meminfo 2>/dev/null)
        [ -n "$FREE_MB" ] || FREE_MB=$(awk '/^MemFree:/ { printf "%d", $2/1024 }' /proc/meminfo 2>/dev/null)
        ;;
    Darwin)
        TOTAL_MB=$(sysctl -n hw.memsize 2>/dev/null | awk '{ printf "%d", $1/1048576 }')
        FREE_MB=$(vm_stat 2>/dev/null | awk '
            /page size of/ { for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) ps = $i }
            /^Pages free:/ { gsub(/\./, "", $3); f = $3 }
            /^Pages inactive:/ { gsub(/\./, "", $3); n = $3 }
            /^Pages speculative:/ { gsub(/\./, "", $3); s = $3 }
            END { if (ps == "") ps = 4096; printf "%d", (f + n + s) * ps / 1048576 }')
        ;;
    AIX)
        TOTAL_MB=$(lsattr -El sys0 -a realmem 2>/dev/null | awk '{ printf "%d", $2/1024 }')
        FREE_MB=$(vmstat 1 1 2>/dev/null | awk 'END { printf "%d", $4*4/1024 }')
        ;;
esac

if [ -n "$CPUS" ]; then
    if [ "$CPUS" -lt 2 ]; then
        warn "CPUs: $CPUS -> THOR switches to soft mode automatically (v10 --nosoft / v11 --no-soft to prevent)"
    else
        ok "CPUs: $CPUS"
    fi
else
    info "CPUs: unknown"
fi
if [ -n "$TOTAL_MB" ]; then
    if [ "$TOTAL_MB" -lt 1024 ]; then
        warn "RAM total: ${TOTAL_MB} MB (< 1024 MB) -> automatic soft mode"
    else
        ok "RAM total: ${TOTAL_MB} MB"
    fi
fi
if [ -n "$FREE_MB" ]; then
    if [ "$FREE_MB" -lt 50 ]; then
        warn "RAM free/available: ${FREE_MB} MB -> THOR refuses to start (< 50 MB) and resource control aborts scans"
    elif [ "$FREE_MB" -lt 500 ]; then
        warn "RAM free/available: ${FREE_MB} MB -> resource control (default floor 50 MB) may stop the scan"
    else
        ok "RAM free/available: ${FREE_MB} MB (approximation)"
    fi
fi

if [ "$OS" = "Linux" ]; then
    section "Linux ulimits (THOR warns if too low)"
    # ulimit -l/-d/-n are not in POSIX but supported by dash, bash, ksh and busybox sh; errors are ignored
    # shellcheck disable=SC3045
    l_mem=$(ulimit -l 2>/dev/null)
    # shellcheck disable=SC3045
    l_data=$(ulimit -d 2>/dev/null)
    # shellcheck disable=SC3045
    l_nofile=$(ulimit -n 2>/dev/null)
    case "$l_mem" in
        ""|unlimited) info "memlock: ${l_mem:-unknown}" ;;
        *) if [ "$l_mem" -lt 64 ]; then warn "memlock: ${l_mem} KB (< 64 KB)"; else ok "memlock: ${l_mem} KB"; fi ;;
    esac
    case "$l_data" in
        ""|unlimited) info "data: ${l_data:-unknown}" ;;
        *) info "data: ${l_data} KB (THOR warns if below file size limit x threads)" ;;
    esac
    case "$l_nofile" in
        ""|unlimited) info "open files: ${l_nofile:-unknown}" ;;
        *) if [ "$l_nofile" -lt 20 ]; then warn "open files: ${l_nofile} (< 20)"; else ok "open files: ${l_nofile}"; fi ;;
    esac
fi

section "Disk space"
check_space "THOR_DIR" "$THOR_DIR"
[ -n "$OUT_DIR" ] && check_space "OUTPUT_DIR" "$OUT_DIR"
check_space "/tmp (scan lock, diagnostics socket)" /tmp

section "THOR installation in $THOR_DIR"
FOUND_BIN=""
EDITION=""
for b in thor-linux-64 thor-linux thor-macosx thor-aix thor64.exe thor.exe \
         thor-lite-linux-64 thor-lite-linux thor-lite-macosx thor64-lite.exe thor-lite.exe; do
    if [ -f "$THOR_DIR/$b" ]; then
        ok "binary: $b"
        case "$b" in *lite*) EDITION=Lite ;; *) [ -n "$EDITION" ] || EDITION=full ;; esac
        case "$b" in *.exe) ;; *) [ -n "$FOUND_BIN" ] || FOUND_BIN=$b ;; esac
    fi
done
for u in thor-util thor-lite-util thor-util.exe thor-lite-util.exe; do
    [ -f "$THOR_DIR/$u" ] && ok "updater: $u"
done
if [ -z "$EDITION" ]; then
    warn "no THOR binary found in $THOR_DIR (pass the THOR program folder as first argument)"
else
    info "edition: $EDITION"
fi

MAJOR=""
if [ -f "$THOR_DIR/config/thor.yml.defaults" ] || [ -f "$THOR_DIR/tools/thunderstorm" ]; then
    MAJOR=11
fi
if [ -n "$FOUND_BIN" ] && [ "$NO_EXEC" -eq 0 ]; then
    if [ -x "$THOR_DIR/$FOUND_BIN" ]; then
        # --version prints and exits before license checks; keep only version lines
        vout=$(cd "$THOR_DIR" && "./$FOUND_BIN" --version 2>/dev/null </dev/null | \
            grep -v -i -e LICENSE_OWNER -e 'License file found' -e 'Scan Information' -e owner | \
            grep -e '^THOR ' -e '^Signature Database' -e '^Sigma Database' | head -n 3)
        if [ -n "$vout" ]; then
            printf '%s\n' "$vout" | sed 's/^/  [INFO] /'
            case "$vout" in
                "THOR 10."*) MAJOR=10 ;;
                "THOR 11."*) MAJOR=11 ;;
            esac
        else
            info "'$FOUND_BIN --version' gave no version output (wrong architecture, blocked by AV/EDR, or not executable)"
        fi
    else
        warn "$FOUND_BIN is not executable (chmod +x, or the folder is mounted noexec)"
    fi
fi
if [ -n "$MAJOR" ]; then
    info "major version: $MAJOR"
else
    info "major version: unknown (check '<binary> --version')"
fi

if [ -d "$THOR_DIR/signatures" ]; then
    recent=$(find "$THOR_DIR/signatures" -type f -mtime -60 2>/dev/null | head -n 1)
    if [ -n "$recent" ]; then
        ok "signatures: updated within the last 60 days"
    else
        warn "signatures: no file newer than 60 days -> run thor-util update (see thor-maintenance skill)"
    fi
else
    warn "signatures/ missing"
fi

if [ -d "$THOR_DIR/custom-signatures" ]; then
    rootfiles=$(find "$THOR_DIR/custom-signatures/." ! -name . -prune -type f \( -name '*.yar' -o -name '*.yara' \
        -o -name '*.yas' -o -name '*.yml' -o -name '*.yaml' -o -name '*.yms' -o -name '*.txt' -o -name '*.dat' \
        -o -name '*.json' -o -name '*.jsos' \) 2>/dev/null | wc -l | tr -d ' ')
    if [ "${rootfiles:-0}" -gt 0 ] && [ "$MAJOR" = "11" ]; then
        warn "custom-signatures: $rootfiles signature file(s) in the folder root; THOR 11 loads only the yara/ sigma/ iocs/ stix/ subfolders"
    else
        ok "custom-signatures present"
    fi
fi

lic_count=$(find "$THOR_DIR" \( -name '*.lic' -o -name '*.LIC' -o -name '*.Lic' \) -type f 2>/dev/null | wc -l | tr -d ' ')
if [ "${lic_count:-0}" -gt 0 ]; then
    ok "license files under THOR_DIR: $lic_count (validity, type and host binding are only shown by THOR itself)"
else
    if [ -n "${THOR_LICENSE:-}" ]; then
        info "no .lic files, but THOR_LICENSE is set in this environment"
    else
        warn "no .lic files under THOR_DIR and THOR_LICENSE not set -> 'No valid license file found'"
    fi
fi

if [ -f "$THOR_DIR/config/thor.yml" ]; then
    keys=$(grep -E '^[[:space:]]*(minmem|max_file_size|max_file_size_intense|cpulimit|max_runtime)[[:space:]]*:' \
        "$THOR_DIR/config/thor.yml" 2>/dev/null)
    if [ -n "$keys" ] && [ "$MAJOR" = "11" ]; then
        warn "config/thor.yml contains THOR 10 keys; in v11 'minmem: 50' means 50 BYTES:"
        printf '%s\n' "$keys" | sed 's/^[[:space:]]*/           /'
    elif [ -n "$keys" ]; then
        info "config/thor.yml sets:"
        printf '%s\n' "$keys" | sed 's/^[[:space:]]*/           /'
    fi
fi

section "ThorDB (default locations)"
for db in /var/lib/thor/thor10.db /var/lib/thor/thor10-lite.db /var/lib/thor/thor.db /var/lib/thor/thor-lite.db \
          "${XDG_STATE_HOME:-$HOME/.local/state}/thor/thor.db" "${XDG_STATE_HOME:-$HOME/.local/state}/thor/thor-lite.db" \
          "$HOME/Library/Application Support/thor/thor.db" "$HOME/Library/Application Support/thor/thor-lite.db"; do
    if [ -f "$db" ]; then
        sz=$(wc -c < "$db" 2>/dev/null | tr -d ' ')
        info "found $db ($sz bytes)"
    fi
done
if [ -d /var/lib/thor ]; then
    if [ -w /var/lib/thor ]; then ok "/var/lib/thor writable"; else info "/var/lib/thor not writable by this user"; fi
else
    info "/var/lib/thor does not exist (created by THOR when run as root)"
fi

section "Running THOR processes (PID and binary only)"
THOR_RE='^thor(-lite)?-(linux(-64)?|macosx|aix)$'
procs=""
ps_ok=1
if [ -r /proc/self/comm ]; then
    # Linux: read /proc/<pid>/comm (binary name, max 15 chars), never cmdline
    for c in /proc/[0-9]*/comm; do
        [ -r "$c" ] || continue
        name=$(cat "$c" 2>/dev/null)
        if printf '%s\n' "$name" | grep -E -q "$THOR_RE"; then
            pid=${c#/proc/}; pid=${pid%/comm}
            procs="${procs}  [INFO] PID $pid: $name
"
        fi
    done
elif pslist=$(ps -A -o pid= -o comm= 2>/dev/null); then
    procs=$(printf '%s\n' "$pslist" | awk -v re="$THOR_RE" '{
        pid = $1; $1 = ""; sub(/^ /, ""); n = split($0, p, "/"); b = p[n]
        if (b ~ re) print "  [INFO] PID " pid ": " b }')
else
    ps_ok=0
fi
if [ "$ps_ok" -eq 0 ]; then
    info "cannot list processes (no /proc and no usable ps)"
elif [ -n "$procs" ]; then
    printf '%s\n' "$procs" | sed '/^$/d'
    info "a running THOR holds the scan lock ('THOR already running') and the diagnostics endpoint"
else
    ok "no THOR scanner process running"
fi

if [ "$OS" = "Darwin" ]; then
    section "macOS privacy (Full Disk Access)"
    if [ "$UID_NUM" -eq 0 ]; then
        if head -c 1 "/Library/Application Support/com.apple.TCC/TCC.db" >/dev/null 2>&1; then
            ok "this terminal appears to have Full Disk Access"
        else
            warn "this terminal likely lacks Full Disk Access: System Settings > Privacy & Security > Full Disk Access"
        fi
    else
        info "run as root to test Full Disk Access; THOR also needs it for the terminal app it runs in"
    fi
fi

printf '\n=== End of check ===\n'
exit 0
