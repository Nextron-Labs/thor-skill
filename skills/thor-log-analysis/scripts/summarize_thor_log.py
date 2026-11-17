#!/usr/bin/env python3
"""Summarize THOR scan logs for triage (THOR 10 and THOR 11).

Auto-detects per file and per line:
  - THOR 10 / THOR 11 text log (default and --keyval / --key-value variants,
    optionally with a syslog prefix)
  - THOR 10 JSON v1 (--jsonfile) and JSON v2 (--jsonfile --jsonv2)
  - THOR 11 JSON v3 (.jsonl, default output; also the older "THOR finding" records)
  - THOR 11 audit trail (.jsonl.zst) and THOR 10 audit trail (gzip): basic counts only
Input may be plain, gzip (.gz) or zstd (.zst; needs Python 3.14+ or the 'zstandard'
module, otherwise decompress first with 'zstd -d'). Directories are walked recursively.

Privacy: every line or record that contains LICENSE_OWNER, "License file found",
license upload info or the THOR 11 "Scan Information" record is dropped before
parsing and never printed (they contain the licensee's name / e-mail).

Python 3.8+, standard library only.
"""

import argparse
import gzip
import io
import json
import os
import re
import sys
from collections import Counter, defaultdict

LEVELS = ["Alert", "Warning", "Notice", "Info", "Debug", "Error"]
FINDING_LEVELS = ("Alert", "Warning", "Notice")
LEVEL_RANK = {"Alert": 0, "Warning": 1, "Notice": 2, "Info": 3, "Debug": 4, "Error": 5}

LOG_EXTENSIONS = (".txt", ".log", ".json", ".jsonl", ".gz", ".zst", ".zstd")

PRIVACY_MARKERS = ("LICENSE_OWNER", "License file found", "Uploading license",
                   "THOR invocation information")

GZIP_MAGIC = b"\x1f\x8b"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"

# <190>Oct  8 11:37:54 host/10.0.0.1 THOR: Alert: MODULE: ...
TEXT_HEADER = re.compile(
    r"^(?:<\d+>)?(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"THOR: (?P<level>[A-Za-z]+): (?P<body>.*)$")
KEY_AT = re.compile(r"\s*([A-Z][A-Z0-9_]*):(?= |$) ?")
NEXT_KEY = re.compile(r" ([A-Z][A-Z0-9_]*):(?= |$)")
KV_PAIR = re.compile(r"([A-Z][A-Z0-9_]*)='((?:[^'\\]|\\.)*)'")
CSV_HASHLIST = re.compile(r"^[0-9a-fA-F]{32},.*,-?\d+\s*$")
VERSION_MSG = re.compile(r"^Thor Version: (\S+)")
VOLUME_CAP = re.compile(
    r"reached the hit limit|triggered more than|Logged more than|reduced logging|"
    r"reached the log limit|log size limit|exiting THOR to prevent", re.I)

TEXT_SUBJECT_KEYS = ("FILE", "IMAGE_FILE", "IMAGE_PATH", "PATH", "ELEMENT", "KEY",
                     "SERVICE_NAME", "PIPE", "LOCATION", "COMMAND", "NAME",
                     "PROCESS_NAME", "ENTRY")


class Finding(object):
    __slots__ = ("source", "fmt", "host", "level", "module", "message", "score",
                 "subject", "subject_type", "reasons", "reason_count")

    def __init__(self, source, fmt, host, level, module, message, score,
                 subject, subject_type, reasons, reason_count):
        self.source = source
        self.fmt = fmt
        self.host = host or "-"
        self.level = level or "-"
        self.module = module or "-"
        self.message = message or ""
        self.score = score
        self.subject = subject or "-"
        self.subject_type = subject_type or ""
        self.reasons = reasons  # list of dicts: name, score, kind, origin
        self.reason_count = reason_count

    def as_dict(self):
        return {
            "file": self.source, "format": self.fmt, "host": self.host,
            "level": self.level, "module": self.module, "message": self.message,
            "score": self.score, "subject": self.subject,
            "subject_type": self.subject_type, "reasons": self.reasons,
            "reason_count": self.reason_count,
        }


def to_int(value):
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


def clip(text, limit=160):
    text = " ".join(str(text).split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def combine_scores(scores):
    """THOR's score combination (10.7 and 11): not additive, capped at 100."""
    ordered = sorted((s for s in scores if s is not None), reverse=True)
    uncertainty = 1.0
    for i, s in enumerate(ordered):
        if s >= 0:
            uncertainty *= 1 - min(s, 100) / 100.0 / (2 ** i)
        else:
            if s <= -100:
                return 0
            uncertainty *= 1 - s / 100.0
    total = 100 * (1 - uncertainty)
    return int(total + 0.5) if total >= 0 else -int(-total + 0.5)


def derive_level(score, reasons):
    top = max([r.get("score") or 0 for r in reasons] or [0])
    if score >= 81 and top >= 76:
        return "Alert"
    if score >= 60:
        return "Warning"
    if score >= 40:
        return "Notice"
    return "Info"


# ---------------------------------------------------------------- input


class InputError(Exception):
    pass


def open_text(path):
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head.startswith(GZIP_MAGIC):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="replace")
    if head.startswith(ZSTD_MAGIC):
        try:  # Python 3.14+ standard library
            from compression import zstd as stdlib_zstd  # type: ignore
            return stdlib_zstd.open(path, "rt", encoding="utf-8", errors="replace")
        except ImportError:
            pass
        try:
            import zstandard  # type: ignore
        except ImportError:
            raise InputError(
                "zstd-compressed file (e.g. a THOR 11 audit trail). Use Python 3.14+, install the "
                "'zstandard' module, or decompress first: zstd -d '%s'" % path)
        reader = zstandard.ZstdDecompressor().stream_reader(open(path, "rb"))
        return io.TextIOWrapper(reader, encoding="utf-8", errors="replace")
    with open(path, "rb") as fh:
        sample = fh.read(8192)
    if b"\x00" in sample:
        raise InputError(
            "binary data: not a THOR log (encrypted logs must be decrypted with "
            "'thor-util decrypt' first)")
    return io.open(path, "r", encoding="utf-8", errors="replace")


def collect_paths(inputs):
    files = []
    for item in inputs:
        if os.path.isdir(item):
            for root, dirs, names in os.walk(item):
                dirs.sort()
                for name in sorted(names):
                    if name.lower().endswith(LOG_EXTENSIONS):
                        files.append(os.path.join(root, name))
        elif os.path.isfile(item):
            files.append(item)
        else:
            raise InputError("no such file or directory: %s" % item)
    return files


# ---------------------------------------------------------------- text log


def find_closing_quote(text, start):
    i = start + 1
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == '"':
            return i
        i += 1
    return -1


def go_unquote(raw):
    try:
        return json.loads(raw)
    except ValueError:
        return raw[1:-1].replace('\\"', '"').replace("\\\\", "\\")


def parse_text_body(body):
    fields = {}
    if body.startswith("MODULE='"):
        for key, value in KV_PAIR.findall(body):
            value = re.sub(r"\\(.)", r"\1", value)
            fields.setdefault(key, value)
        return fields
    pos = 0
    m = KEY_AT.match(body, pos)
    while m:
        key = m.group(1)
        pos = m.end()
        if body.startswith('"', pos):
            end = find_closing_quote(body, pos)
            if end != -1:
                fields.setdefault(key, go_unquote(body[pos:end + 1]))
                pos = end + 1
                m = KEY_AT.match(body, pos)
                if m:
                    continue
                nm = NEXT_KEY.search(body, pos)
                if not nm:
                    break
                m = KEY_AT.match(body, nm.start())
                continue
        nm = NEXT_KEY.search(body, pos)
        if nm:
            fields.setdefault(key, body[pos:nm.start()].strip())
            m = KEY_AT.match(body, nm.start())
        else:
            fields.setdefault(key, body[pos:].strip())
            m = None
    return fields


def text_subject(f):
    if "EVENT_ID" in f:
        return "%s EventID %s" % (f.get("EVENT_CHANNEL", "?"), f.get("EVENT_ID")), "eventlog entry"
    if "PID" in f:
        name = f.get("IMAGE_FILE") or f.get("PROCESS_NAME") or f.get("NAME") or f.get("COMMAND", "?")
        return "%s (PID %s)" % (name, f.get("PID")), "process"
    if "LINE" in f:
        owner = f.get("PARENT_FILE") or f.get("FILE") or "?"
        return "%s: %s" % (owner, f.get("LINE")), "log line"
    for key in TEXT_SUBJECT_KEYS:
        if f.get(key):
            return f[key], ""
    return "", ""


YARA_SUMMARY = re.compile(r"^YARA rule (\S+)")
SIGMA_SUMMARY = re.compile(r"^Sigma rule (.+)$")


def rule_key(rule_name, summary):
    """Stable rule label across versions: rule name if present, else parsed from the summary."""
    if rule_name:
        return rule_name
    summary = summary or "-"
    m = YARA_SUMMARY.match(summary) or SIGMA_SUMMARY.match(summary)
    return m.group(1) if m else summary


def reasons_from_flat(get):
    reasons = []
    n = 1
    while True:
        summary = get("reason_%d" % n)
        if summary is None and get("subscore_%d" % n) is None:
            break
        reasons.append({
            "name": rule_key(get("rulename_%d" % n), summary),
            "score": to_int(get("subscore_%d" % n)),
            "kind": get("sigclass_%d" % n) or "",
            "origin": get("sigtype_%d" % n) or "",
        })
        n += 1
    return reasons


# ---------------------------------------------------------------- JSON


def v3_subject(subject, ancestors):
    if not isinstance(subject, dict):
        return "", ""
    stype = subject.get("type", "")
    if stype == "log line":
        parent = "?"
        for anc in ancestors or []:
            obj = (anc or {}).get("object") or {}
            if (anc or {}).get("distance") == 1 and obj.get("path"):
                parent = obj["path"]
        return "%s:%s %s" % (parent, subject.get("line_index", "?"), subject.get("line", "")), stype
    if stype == "eventlog entry":
        return "%s EventID %s" % (subject.get("channel", "?"), subject.get("event_id")), stype
    if stype == "process":
        image = (subject.get("image") or {}).get("path") or subject.get("name") or "?"
        pid = subject.get("pid")
        return ("%s (PID %s)" % (image, pid) if pid is not None else image), stype
    for key in ("path", "key", "service_name", "pipe", "location", "name", "command", "entry"):
        val = subject.get(key)
        if isinstance(val, str) and val:
            return val, stype
    for key in ("file", "image"):
        val = subject.get(key)
        if isinstance(val, dict) and val.get("path"):
            return val["path"], stype
    return "", stype


def v10_json_subject(obj):
    if "event_id" in obj:
        return "%s EventID %s" % (obj.get("event_channel", "?"), obj.get("event_id")), "eventlog entry"
    if "pid" in obj:
        img = obj.get("image")
        name = (img.get("path") if isinstance(img, dict) else None) or obj.get("image_file") \
            or obj.get("process_name") or obj.get("name") or "?"
        return "%s (PID %s)" % (name, obj.get("pid")), "process"
    for key in ("file", "image_file", "image_path", "path", "element", "key", "service_name",
                "pipe", "location", "command", "name", "entry"):
        val = obj.get(key)
        if isinstance(val, dict):
            val = val.get("path")
        if isinstance(val, str) and val:
            return val, ""
    return "", ""


# ---------------------------------------------------------------- summary


class Summary(object):
    def __init__(self, include_info):
        self.include_info = include_info
        self.files = []          # dicts: path, formats, versions, end_summary, note
        self.findings = []
        self.levels = Counter()  # findings (scored records / assessments)
        self.messages = Counter()  # non-finding records by level
        self.modules = Counter()
        self.subject_types = Counter()
        self.hosts = defaultdict(Counter)
        self.rules = {}
        self.errors = Counter()
        self.unscored = Counter()
        self.volume_caps = Counter()
        self.truncated_reasons = 0
        self.dropped_private = 0
        self.unparsed = 0
        self.versions = set()

    # -- per record
    def add_finding(self, fd):
        self.levels[fd.level] += 1
        self.hosts[fd.host][fd.level] += 1
        if fd.level not in FINDING_LEVELS and not self.include_info:
            return
        self.findings.append(fd)
        self.modules[fd.module] += 1
        if fd.subject_type:
            self.subject_types[fd.subject_type] += 1
        if fd.reason_count and fd.reason_count > len(fd.reasons):
            self.truncated_reasons += 1
        for r in fd.reasons:
            key = r["name"]
            entry = self.rules.setdefault(key, {
                "name": key, "count": 0, "hosts": set(), "max_subscore": None,
                "kind": r.get("kind") or "", "origin": r.get("origin") or "",
                "levels": Counter()})
            entry["count"] += 1
            entry["hosts"].add(fd.host)
            entry["levels"][fd.level] += 1
            if r.get("score") is not None and (entry["max_subscore"] is None or r["score"] > entry["max_subscore"]):
                entry["max_subscore"] = r["score"]

    def add_message(self, host, level, module, message, finfo):
        level = level or "-"
        self.messages[level] += 1
        m = VERSION_MSG.match(message or "")
        if m:
            finfo["versions"].add(m.group(1))
            self.versions.add(m.group(1))
        if level == "Error":
            self.errors[(module or "-", clip(message, 120))] += 1
            self.hosts[host or "-"]["Error"] += 1
        elif level in FINDING_LEVELS:
            self.unscored[(level, module or "-", clip(message, 120))] += 1
        if message and VOLUME_CAP.search(message):
            self.volume_caps[(module or "-", clip(message, 140))] += 1

    # -- formats
    def handle_text(self, m, finfo):
        host = m.group("host").split("/")[0]
        level = m.group("level")
        fields = parse_text_body(m.group("body"))
        module = fields.get("MODULE", "")
        message = fields.get("MESSAGE", "")
        finfo["formats"].add("text-kv" if m.group("body").startswith("MODULE='") else "text")
        if module == "Report" and message in ("Results", "Assessments", "Messages"):
            counts = {}
            for k, v in fields.items():
                short = re.sub(r"^(ASSESSMENTS|MESSAGES)_", "", k)
                if short in ("ALERTS", "WARNINGS", "NOTICES", "INFOS", "ERRORS"):
                    counts[short.lower()] = to_int(v)
            if message == "Messages":  # THOR 11: message counters, keep only the error count
                counts = {"errors": counts["errors"]} if "errors" in counts else {}
            finfo["end_summary"].update(counts)
        score = to_int(fields.get("SCORE"))
        if score is None:
            self.add_message(host, level, module, message, finfo)
            return
        subject, stype = text_subject(fields)
        reasons = reasons_from_flat(lambda k: fields.get(k.upper()))
        self.add_finding(Finding(finfo["path"], "text", host, level, module, message, score,
                                 clip(subject), stype, reasons, to_int(fields.get("REASONS_COUNT"))))

    def handle_json(self, obj, finfo):
        rtype = obj.get("type") if isinstance(obj.get("type"), str) else None
        if rtype in ("THOR assessment", "THOR finding"):
            finfo["formats"].add("json-v3")
            meta = obj.get("meta") or {}
            reasons = []
            for r in obj.get("reasons") or []:
                sig = (r or {}).get("signature") or {}
                reasons.append({"name": rule_key(sig.get("rule_name"), r.get("summary")),
                                "score": to_int(sig.get("score")),
                                "kind": sig.get("kind") or "", "origin": sig.get("origin") or ""})
            subject, stype = v3_subject(obj.get("subject"), obj.get("ancestors"))
            self.add_finding(Finding(finfo["path"], "json-v3", meta.get("hostname"), meta.get("level"),
                                     meta.get("module"), obj.get("message"), to_int(obj.get("score")),
                                     clip(subject), stype, reasons, to_int(obj.get("reason_count"))))
            return
        if rtype == "THOR message":
            finfo["formats"].add("json-v3")
            meta = obj.get("meta") or {}
            fields = obj.get("fields") or {}
            if meta.get("module") == "Report" and isinstance(fields.get("assessments"), dict):
                finfo["end_summary"].update(fields["assessments"])
            if meta.get("module") == "Report" and isinstance(fields.get("messages"), dict):
                finfo["end_summary"]["errors"] = fields["messages"].get("errors")
            self.add_message(meta.get("hostname"), meta.get("level"), meta.get("module"),
                             obj.get("message"), finfo)
            return
        if rtype == "THOR audit record":
            finfo["formats"].add("audit-trail-v11")
            reasons = []
            for r in obj.get("reasons") or []:
                sig = (r or {}).get("signature") or {}
                reasons.append({"name": rule_key(sig.get("rule_name"), r.get("summary")),
                                "score": to_int(sig.get("score")),
                                "kind": sig.get("kind") or "", "origin": sig.get("origin") or ""})
            finfo["audit_records"] = finfo.get("audit_records", 0) + 1
            if not reasons:
                return
            score = combine_scores([r["score"] for r in reasons if r["score"] is not None])
            subject, stype = v3_subject(obj.get("object"), None)
            self.add_finding(Finding(finfo["path"], "audit-trail-v11", finfo.get("host_hint"),
                                     derive_level(score, reasons), "(audit trail)", "audit record", score,
                                     clip(subject), stype, reasons, len(reasons)))
            return
        if rtype == "THOR audit message":
            finfo["formats"].add("audit-trail-v11")
            self.add_message(finfo.get("host_hint"), obj.get("level"), obj.get("module"),
                             obj.get("message"), finfo)
            return
        if "info" in obj and "findings" in obj:
            finfo["formats"].add("audit-trail-v10")
            info = obj.get("info") or {}
            for f in obj.get("findings") or []:
                f = f or {}
                self.add_finding(Finding(finfo["path"], "audit-trail-v10", finfo.get("host_hint"),
                                         f.get("Level"), f.get("Module"), f.get("Message"), None,
                                         clip(info.get("Name") or ""), "", [], None))
            return
        if "level" in obj and "module" in obj:
            version = obj.get("log_version") or "v1.0.0"
            fmt = "json-v2" if str(version).startswith("v2") or isinstance(obj.get("reasons"), list) else "json-v1"
            finfo["formats"].add(fmt)
            host, level, module, message = obj.get("hostname"), obj.get("level"), obj.get("module"), obj.get("message")
            if module == "Report" and "alerts" in obj:
                finfo["end_summary"] = {k: obj.get(k) for k in ("alerts", "warnings", "notices", "errors") if k in obj}
            score = to_int(obj.get("score"))
            if score is None:
                self.add_message(host, level, module, message, finfo)
                return
            if fmt == "json-v2":
                reasons = []
                for r in obj.get("reasons") or []:
                    sig = (r or {}).get("signature") or {}
                    reasons.append({"name": rule_key(sig.get("rulename"), r.get("name")),
                                    "score": to_int(r.get("score")),
                                    "kind": r.get("sigclass") or "", "origin": r.get("sigtype") or ""})
                rcount = to_int(obj.get("reasons_count"))
            else:
                reasons = reasons_from_flat(lambda k: obj.get(k))
                rcount = to_int(obj.get("reasons_count"))
            subject, stype = v10_json_subject(obj)
            self.add_finding(Finding(finfo["path"], fmt, host, level, module, message, score,
                                     clip(subject), stype, reasons, rcount))
            return
        self.unparsed += 1

    def process_file(self, path):
        base = os.path.basename(path)
        finfo = {"path": path, "formats": set(), "versions": set(), "end_summary": {}, "note": "",
                 "host_hint": re.split(r"_thor_audit|_audit|_thor_", base)[0]}
        self.files.append(finfo)
        try:
            fh = open_text(path)
        except (InputError, OSError) as exc:
            finfo["note"] = "skipped: %s" % exc
            return
        with fh:
            first = True
            for raw in fh:
                line = raw.strip()
                if not line:
                    continue
                if first:
                    first = False
                    low = line[:200].lower()
                    if low.startswith("<!doctype html") or low.startswith("<html"):
                        finfo["note"] = "skipped: HTML report (open it in a browser; analyze the .txt/.jsonl log instead)"
                        return
                    if CSV_HASHLIST.match(line):
                        finfo["formats"].add("csv-hashlist")
                        finfo["note"] = "hash list CSV (md5,path,score): use it for hash lookups, not for triage"
                        return
                if any(marker in line for marker in PRIVACY_MARKERS):
                    self.dropped_private += 1
                    continue
                if line.startswith("{") or " THOR: {" in line:
                    payload = line if line.startswith("{") else line[line.index(" THOR: {") + 7:]
                    try:
                        obj = json.loads(payload)
                    except ValueError:
                        self.unparsed += 1
                        continue
                    if not isinstance(obj, dict):
                        self.unparsed += 1
                        continue
                    if obj.get("message") == "Scan Information":  # THOR 11: contains license owner
                        self.dropped_private += 1
                        continue
                    self.handle_json(obj, finfo)
                    continue
                m = TEXT_HEADER.match(line)
                if m:
                    self.handle_text(m, finfo)
                else:
                    self.unparsed += 1

    # -- output
    def rules_sorted(self, top):
        rows = sorted(self.rules.values(),
                      key=lambda r: (min(LEVEL_RANK.get(l, 9) for l in r["levels"]),
                                     -(r["max_subscore"] or 0), -r["count"], r["name"]))
        return rows[:top]

    def top_findings(self, top):
        rows = sorted(self.findings, key=lambda f: (LEVEL_RANK.get(f.level, 9), -(f.score or 0), f.host))
        return rows[:top]

    def to_dict(self, top):
        return {
            "files": [{"path": f["path"], "formats": sorted(f["formats"]), "thor_versions": sorted(f["versions"]),
                       "end_of_scan_summary": f["end_summary"] or None,
                       "audit_records": f.get("audit_records"), "note": f["note"] or None}
                      for f in self.files],
            "hosts": {h: dict(c) for h, c in sorted(self.hosts.items())},
            "finding_levels": dict(self.levels),
            "message_levels": dict(self.messages),
            "modules": dict(self.modules.most_common()),
            "subject_types": dict(self.subject_types.most_common()),
            "top_rules": [{"name": r["name"], "findings": r["count"], "hosts": len(r["hosts"]),
                           "max_subscore": r["max_subscore"], "kind": r["kind"], "origin": r["origin"],
                           "levels": dict(r["levels"])} for r in self.rules_sorted(top)],
            "top_findings": [f.as_dict() for f in self.top_findings(top)],
            "errors": [{"module": k[0], "message": k[1], "count": v} for k, v in self.errors.most_common(top)],
            "unscored_alert_warning_notice": [{"level": k[0], "module": k[1], "message": k[2], "count": v}
                                              for k, v in self.unscored.most_common(top)],
            "volume_caps": [{"module": k[0], "message": k[1], "count": v} for k, v in self.volume_caps.most_common(top)],
            "findings_with_truncated_reasons": self.truncated_reasons,
            "dropped_private_lines": self.dropped_private,
            "unparsed_lines": self.unparsed,
        }

    def print_text(self, top, out):
        w = out.write
        nhosts = len(self.hosts)
        w("THOR log summary\n================\n")
        for f in self.files:
            fmts = ", ".join(sorted(f["formats"])) or "-"
            ver = ", ".join(sorted(f["versions"])) or "?"
            if f["end_summary"]:
                end = "end-of-scan summary: " + " ".join("%s=%s" % (k, v) for k, v in sorted(f["end_summary"].items()))
            elif f["formats"] & {"text", "text-kv", "json-v1", "json-v2", "json-v3"}:
                end = "NO end-of-scan summary (scan aborted, still running or log incomplete)"
            else:
                end = ""
            w("- %s [%s] THOR %s %s\n" % (f["path"], fmts, ver, end))
            if f.get("audit_records"):
                w("    audit trail: %d records; findings below use derived scores. Use THOR Lens for timeline work.\n"
                  % f["audit_records"])
            if f["note"]:
                w("    %s\n" % f["note"])
        w("\nFindings by level: %s\n" % (", ".join("%s %d" % (l, self.levels[l]) for l in LEVELS if self.levels[l]) or "none"))
        w("Messages by level: %s\n" % (", ".join("%s %d" % (l, self.messages[l]) for l in LEVELS if self.messages[l]) or "none"))
        if self.dropped_private:
            w("Dropped %d license/owner line(s) (never printed).\n" % self.dropped_private)
        if self.unparsed:
            w("Unparsed lines: %d (console output, truncated lines or unknown format)\n" % self.unparsed)
        if not self.include_info and (self.levels["Info"] or self.levels["Debug"]):
            w("Info/Debug assessments are counted but excluded from the tables (use --include-info).\n")

        if nhosts:
            w("\nPer host (%d)\n" % nhosts)
            w("  %-32s %6s %7s %6s %6s %6s\n" % ("host", "Alert", "Warning", "Notice", "Info", "Error"))
            for host, c in sorted(self.hosts.items(), key=lambda kv: (-kv[1]["Alert"], -kv[1]["Warning"], kv[0])):
                w("  %-32s %6d %7d %6d %6d %6d\n" % (clip(host, 32), c["Alert"], c["Warning"], c["Notice"],
                                                     c["Info"], c["Error"]))
        if self.modules:
            w("\nModules: %s\n" % ", ".join("%s %d" % kv for kv in self.modules.most_common(top)))
        if self.subject_types:
            w("Object types: %s\n" % ", ".join("%s %d" % kv for kv in self.subject_types.most_common(top)))

        rules = self.rules_sorted(top)
        if rules:
            w("\nTop rules / reasons (hosts = spread; rare beats common)\n")
            w("  %5s %5s %4s  %-18s %-8s %s\n" % ("count", "hosts", "max", "kind", "origin", "rule / reason"))
            for r in rules:
                w("  %5d %5d %4s  %-18s %-8s %s\n" % (r["count"], len(r["hosts"]),
                                                       "-" if r["max_subscore"] is None else r["max_subscore"],
                                                       clip(r["kind"], 18), clip(r["origin"], 8), clip(r["name"], 100)))
        tops = self.top_findings(top)
        if tops:
            w("\nTop findings\n")
            for f in tops:
                first = f.reasons[0]["name"] if f.reasons else f.message
                extra = ""
                if f.reason_count and f.reason_count > len(f.reasons):
                    extra = " (+%d hidden reasons)" % (f.reason_count - len(f.reasons))
                w("  %-7s %4s  %-20s %-14s %s\n      -> %s%s\n" % (
                    f.level, "-" if f.score is None else f.score, clip(f.host, 20), clip(f.module, 14),
                    f.subject, clip(first, 120), extra))
        if self.truncated_reasons:
            w("\n%d finding(s) show fewer reasons than REASONS_COUNT/reason_count (default limit 2; "
              "rescan with --max-reasons 0 (v10) / --alert-reason-limit 0 (v11) to see all).\n" % self.truncated_reasons)
        if self.volume_caps:
            w("\nVolume caps hit (counts below are incomplete)\n")
            for (mod, msg), n in self.volume_caps.most_common(top):
                w("  %4dx %-12s %s\n" % (n, mod, msg))
        if self.unscored:
            w("\nAlert/Warning/Notice lines without a score (messages, or v10 findings logged without SCORE)\n")
            for (lvl, mod, msg), n in self.unscored.most_common(top):
                w("  %4dx %-7s %-14s %s\n" % (n, lvl, clip(mod, 14), msg))
        if self.errors:
            w("\nErrors\n")
            for (mod, msg), n in self.errors.most_common(top):
                w("  %4dx %-14s %s\n" % (n, clip(mod, 14), msg))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Summarize THOR 10/11 logs (text, JSON v1/v2/v3, .gz/.zst) for triage. "
                    "License owner lines are always dropped.")
    ap.add_argument("inputs", nargs="+", help="log files and/or directories (walked recursively for "
                                              + ", ".join(LOG_EXTENSIONS) + ")")
    ap.add_argument("--top", type=int, default=15, metavar="N", help="rows per table (default 15)")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON")
    ap.add_argument("--include-info", action="store_true",
                    help="also list Info/Debug assessments in the tables (THOR 11 logs many Info objects)")
    args = ap.parse_args(argv)
    if args.top < 1:
        ap.error("--top must be >= 1")
    try:
        paths = collect_paths(args.inputs)
    except InputError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2
    if not paths:
        sys.stderr.write("error: no log files found in the given directories\n")
        return 2
    summary = Summary(args.include_info)
    for path in paths:
        summary.process_file(path)
    if args.json:
        json.dump(summary.to_dict(args.top), sys.stdout, indent=2, sort_keys=False, default=str)
        sys.stdout.write("\n")
    else:
        summary.print_text(args.top, sys.stdout)
    if all(f["note"].startswith("skipped") for f in summary.files):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
