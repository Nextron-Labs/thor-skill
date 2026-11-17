#!/usr/bin/env python3
"""Export the plaintext ThorDB tables `stats` and `times` to CSV or JSON, read-only.

Works on v10 (thor10.db, `times` without `count`) and v11 (thor.db, `times` with `count`).
The encrypted `tbl` table is never exported. Output files are written to --outdir
(default: current directory); the DB itself is opened with mode=ro and never modified.
"""
import argparse
import csv
import json
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


def query_stats(conn):
    # started is stored as text 'YYYY-MM-DD HH:MM:SS[.fffffffff]+00:00' (UTC); duration in whole seconds
    cur = conn.execute(
        "SELECT module, element, started, datetime(started) AS started_utc, duration AS duration_seconds "
        "FROM stats ORDER BY started")
    return [d[0] for d in cur.description], cur.fetchall()


def query_times(conn):
    cols = [r[1] for r in conn.execute("PRAGMA table_info(times)")]
    if "count" in cols:
        cur = conn.execute(
            "SELECT category, element, count, duration AS duration_ns, duration/1e9 AS duration_seconds "
            "FROM times ORDER BY duration DESC")
    else:
        cur = conn.execute(
            "SELECT category, element, duration AS duration_ns, duration/1e9 AS duration_seconds "
            "FROM times ORDER BY duration DESC")
    return [d[0] for d in cur.description], cur.fetchall()


def write(outdir, name, header, rows, as_json, force):
    path = os.path.join(outdir, name + (".json" if as_json else ".csv"))
    if os.path.exists(path) and not force:
        sys.exit("error: %s exists (use --force to overwrite)" % path)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        if as_json:
            json.dump([dict(zip(header, r)) for r in rows], fh, indent=2)
            fh.write("\n")
        else:
            w = csv.writer(fh)
            w.writerow(header)
            w.writerows(rows)
    print("wrote %d rows to %s" % (len(rows), path))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("db", help="path to the ThorDB file")
    ap.add_argument("-t", "--table", choices=["stats", "times", "all"], default="all", help="table(s) to export")
    ap.add_argument("-o", "--outdir", default=".", help="output directory (default: current directory)")
    ap.add_argument("--json", action="store_true", help="write JSON instead of CSV")
    ap.add_argument("--force", action="store_true", help="overwrite existing output files")
    ap.add_argument("--copy", action="store_true", help="read a temporary copy (use while THOR is running)")
    args = ap.parse_args()

    if not os.path.isdir(args.outdir):
        sys.exit("error: output directory does not exist: %s" % args.outdir)
    if os.path.realpath(args.outdir) == os.path.realpath(os.path.dirname(os.path.abspath(args.db))):
        print("note: writing next to the DB file; consider a separate --outdir", file=sys.stderr)

    conn, tmpdir = open_ro(args.db, args.copy)
    try:
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"stats", "times"} <= tables:
            sys.exit("error: not a ThorDB file (stats/times tables missing)")
        if args.table in ("stats", "all"):
            write(args.outdir, "thordb_stats", *query_stats(conn), as_json=args.json, force=args.force)
        if args.table in ("times", "all"):
            write(args.outdir, "thordb_times", *query_times(conn), as_json=args.json, force=args.force)
    except sqlite3.Error as exc:
        sys.exit("error: SQLite: %s" % exc)
    finally:
        conn.close()
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
