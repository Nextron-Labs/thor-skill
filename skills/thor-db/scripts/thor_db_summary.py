#!/usr/bin/env python3
"""Summarise a THOR ThorDB file (v10 thor10.db / v11 thor.db) read-only.

Shows: detected schema version, module totals and slowest directories from `stats`,
and per-category totals from `times`, with interpretation hints. Never writes to the DB.
The encrypted `tbl` table is only counted.
"""
import argparse
import os
import shutil
import sqlite3
import sys
import tempfile

CATEGORY_HINTS = {
    "deep_scan": "DEEPSCAN selector rules; time spent content-scanning the files they selected. "
                 "Do not filter selectors (that stops deep scanning that file type); exclude folders instead.",
    "bulk_scan": "Rules/IOCs that caused a data chunk to be checked in detail. A custom rule here may be too broad.",
    "feature_scan": "(v10) Meta rules that triggered a feature scanner.",
    "hook": "(v11) Internal processing steps (hooks).",
}


def open_ro(path, copy):
    """Open the DB read-only; optionally from a temporary copy. Returns (conn, tmpdir or None)."""
    if not os.path.isfile(path):
        sys.exit("error: file not found: %s" % path)
    if not os.access(path, os.R_OK):
        sys.exit("error: no read permission for %s (ThorDB folders are root/Administrator only; "
                 "copy the file with elevated rights first)" % path)
    tmpdir = None
    if copy:
        tmpdir = tempfile.mkdtemp(prefix="thordb-")
        dst = os.path.join(tmpdir, "thordb-copy.db")
        shutil.copyfile(path, dst)
        path = dst
    uri = "file:%s?mode=ro" % os.path.abspath(path).replace("?", "%3f").replace("#", "%23")
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
    except sqlite3.DatabaseError as exc:
        cleanup(tmpdir)
        sys.exit("error: cannot read %s as SQLite: %s (locked by a running THOR? retry with --copy)" % (path, exc))
    return conn, tmpdir


def cleanup(tmpdir):
    if tmpdir:
        shutil.rmtree(tmpdir, ignore_errors=True)


def schema(conn):
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    missing = {"tbl", "stats", "times"} - tables
    if missing:
        sys.exit("error: not a ThorDB file (missing tables: %s)" % ", ".join(sorted(missing)))
    cols = [r[1] for r in conn.execute("PRAGMA table_info(times)")]
    has_count = "count" in cols
    return {"has_count": has_count, "version": "v11" if has_count else "v10"}


def fmt_secs(s):
    s = int(s)
    if s >= 3600:
        return "%dh%02dm" % (s // 3600, (s % 3600) // 60)
    if s >= 60:
        return "%dm%02ds" % (s // 60, s % 60)
    return "%ds" % s


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("db", help="path to thor10.db / thor10-lite.db / thor.db / thor-lite.db")
    ap.add_argument("-n", "--top", type=int, default=10, help="rows per section (default 10)")
    ap.add_argument("--copy", action="store_true", help="read a temporary copy (use while THOR is running)")
    args = ap.parse_args()

    conn, tmpdir = open_ro(args.db, args.copy)
    try:
        info = schema(conn)
        n_tbl = conn.execute("SELECT COUNT(*) FROM tbl").fetchone()[0]
        print("ThorDB: %s" % args.db)
        print("Schema: %s (times.count column %s)" % (info["version"], "present" if info["has_count"] else "absent"))
        print("Encrypted key/value entries (tbl): %d  (resume state, delta baselines; not readable)" % n_tbl)
        print("Note: stats/times describe only the LAST run that used this DB.\n")

        mods = conn.execute(
            "SELECT module, duration, datetime(started) FROM stats WHERE element='Whole Module' "
            "ORDER BY duration DESC").fetchall()
        print("== Completed modules (stats, Whole Module) ==")
        if not mods:
            print("  none (no module finished, or the last run had no ThorDB activity)")
        for m, d, st in mods:
            print("  %-20s %10s  started %s UTC" % (m, fmt_secs(d), st))

        rows = conn.execute(
            "SELECT module, element, duration FROM stats WHERE element <> 'Whole Module' "
            "ORDER BY duration DESC LIMIT ?", (args.top,)).fetchall()
        print("\n== Slowest roots / directories / event logs (stats) ==")
        if not rows:
            print("  none")
        for m, e, d in rows:
            print("  %10s  %-12s %s" % (fmt_secs(d), m, e))
        if rows:
            print("  (directories nest: a root includes its subfolders; folders appear down to depth 2 or when >= 20 s)")

        print("\n== times per category ==")
        cats = conn.execute(
            "SELECT category, COUNT(*), SUM(duration) FROM times GROUP BY category ORDER BY SUM(duration) DESC"
        ).fetchall()
        if not cats:
            print("  empty: the last run was killed/crashed, is still running, or had no ThorDB (times are written at exit)")
        for cat, entries, total in cats:
            print("  %-13s %4d entries  %10s total" % (cat, entries, fmt_secs((total or 0) / 1e9)))
            print("      %s" % CATEGORY_HINTS.get(cat, "unknown category"))
            if info["has_count"]:
                top = conn.execute(
                    "SELECT element, count, duration FROM times WHERE category=? ORDER BY duration DESC LIMIT ?",
                    (cat, min(args.top, 5))).fetchall()
                for el, cnt, dur in top:
                    print("        %10s  x%-7d %s" % (fmt_secs(dur / 1e9), cnt, el))
            else:
                top = conn.execute(
                    "SELECT element, duration FROM times WHERE category=? ORDER BY duration DESC LIMIT ?",
                    (cat, min(args.top, 5))).fetchall()
                for el, dur in top:
                    print("        %10s  %s" % (fmt_secs(dur / 1e9), el))
    except sqlite3.Error as exc:
        sys.exit("error: SQLite: %s" % exc)
    finally:
        conn.close()
        cleanup(tmpdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
