#!/usr/bin/env python3
"""List the top entries of the ThorDB `times` table (v10 thor10.db and v11 thor.db), read-only.

v10 has no `count` column (categories feature_scan, deep_scan, bulk_scan);
v11 adds `count` (categories hook, deep_scan, bulk_scan). Durations are stored in nanoseconds.
Only the last run that used the DB is covered; the table is written at clean exit only.
"""
import argparse
import csv
import os
import shutil
import sqlite3
import sys
import tempfile


def open_ro(path, copy):
    if not os.path.isfile(path):
        sys.exit("error: file not found: %s" % path)
    if not os.access(path, os.R_OK):
        sys.exit("error: no read permission for %s (copy it with elevated rights first)" % path)
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
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
        sys.exit("error: cannot read %s as SQLite: %s (locked? retry with --copy)" % (path, exc))
    return conn, tmpdir


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("db", help="path to the ThorDB file")
    ap.add_argument("-n", "--top", type=int, default=20, help="number of rows (default 20)")
    ap.add_argument("-c", "--category", help="only this category (deep_scan, bulk_scan, hook, feature_scan)")
    ap.add_argument("--csv", action="store_true", help="CSV output on stdout")
    ap.add_argument("--copy", action="store_true", help="read a temporary copy (use while THOR is running)")
    args = ap.parse_args()

    conn, tmpdir = open_ro(args.db, args.copy)
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "times" not in tables:
            sys.exit("error: no `times` table: not a ThorDB file")
        cols = [r[1] for r in conn.execute("PRAGMA table_info(times)")]
        has_count = "count" in cols
        sel = "category, element, %s duration" % ("count," if has_count else "")
        sql = "SELECT %s FROM times" % sel
        params = []
        if args.category:
            sql += " WHERE category = ?"
            params.append(args.category)
        sql += " ORDER BY duration DESC LIMIT ?"
        params.append(args.top)
        rows = conn.execute(sql, params).fetchall()
        if not rows:
            known = [r[0] for r in conn.execute("SELECT DISTINCT category FROM times")]
            print("no rows%s; categories present: %s" % (
                " for category %r" % args.category if args.category else "",
                ", ".join(known) or "none (run killed/crashed, still running, or no ThorDB)"), file=sys.stderr)
            return 1
        header = ["category", "element"] + (["count"] if has_count else []) + ["seconds"] + (
            ["avg_ms"] if has_count else [])
        out = []
        for r in rows:
            if has_count:
                cat, el, cnt, dur = r
                avg = "%.2f" % (dur / cnt / 1e6) if cnt else ""
                out.append([cat, el, cnt, "%.1f" % (dur / 1e9), avg])
            else:
                cat, el, dur = r
                out.append([cat, el, "%.1f" % (dur / 1e9)])
        if args.csv:
            w = csv.writer(sys.stdout)
            w.writerow(header)
            w.writerows(out)
        else:
            print("schema: %s" % ("v11 (with count)" if has_count else "v10 (no count column)"))
            print("\t".join(header))
            for r in out:
                print("\t".join(str(x) for x in r))
    except sqlite3.Error as exc:
        sys.exit("error: SQLite: %s" % exc)
    finally:
        conn.close()
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
