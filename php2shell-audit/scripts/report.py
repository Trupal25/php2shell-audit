#!/usr/bin/env python3
"""Aggregate PHP2Shell JSONL findings into Markdown and CSV.

Usage:
  report.py --input fleet.jsonl --md report.md --csv findings.csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from datetime import datetime, timezone

PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "PATCHED": 4, "UNKNOWN": 5}


def load(path: str) -> list[dict]:
    records: list[dict] = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                print(f"skip {path}:{lineno}: {exc}", file=sys.stderr)
                continue
            if isinstance(obj, dict):
                records.append(obj)
    return records


def first(record: dict, *keys: str, default: str = "") -> str:
    for key in keys:
        value = record.get(key)
        if value not in (None, "", [], {}):
            return str(value)
    return default


def version_tuple(value: str) -> tuple[int, ...]:
    parts = []
    for piece in str(value).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def normalize(record: dict) -> dict:
    priority = first(record, "priority", "decision", default="UNKNOWN").upper()
    version = first(record, "php_version", "version")
    gate = first(record, "patched_min", "gate")
    evidence = record.get("evidence") or []
    if isinstance(evidence, dict):
        evidence = [evidence]
    interim = record.get("interim_controls") or {}
    edge = record.get("edge_controls") or {}
    flags: list[str] = []
    if not evidence:
        flags.append("no evidence")
    if not first(record, "owner"):
        flags.append("no owner")
    if first(record, "status") == "vulnerable" and not gate:
        flags.append("no patch gate recorded")
    if priority in ("PATCHED", "P3") and first(record, "status") == "vulnerable":
        flags.append("priority/status mismatch")
    if version and gate:
        if first(record, "status") == "patched" and version_tuple(version) < version_tuple(gate):
            flags.append("marked patched below gate")
        if first(record, "status") == "vulnerable" and version_tuple(version) >= version_tuple(gate):
            flags.append("marked vulnerable at/above gate")
    return {
        "asset": first(record, "asset", "host", default="unknown"),
        "priority": priority,
        "status": first(record, "status", default="unknown"),
        "sapi": first(record, "sapi", default="unknown"),
        "version": version or "unknown",
        "gate": gate or "none",
        "exposure": first(record, "exposure", default="unknown"),
        "owner": first(record, "owner", default=""),
        "remediation": first(record, "remediation", default=""),
        "verified_at": first(record, "verified_at", "checked_at", default=""),
        "evidence_count": len(evidence),
        "interim_count": len(interim) if isinstance(interim, dict) else 0,
        "edge_count": len(edge) if isinstance(edge, dict) else 0,
        "flags": flags,
        "record": record,
    }


def sort_key(row: dict) -> tuple:
    return (PRIORITY_ORDER.get(row["priority"], 9), row["asset"])


def build_markdown(rows: list[dict], title: str) -> str:
    counts = Counter(row["priority"] for row in rows)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# {title}",
        "",
        f"Generated: {now}",
        "",
        f"**Assets:** {len(rows)}  ",
        f"**P0:** {counts.get('P0', 0)} · **P1:** {counts.get('P1', 0)} · "
        f"**P2:** {counts.get('P2', 0)} · **P3:** {counts.get('P3', 0)} · "
        f"**Patched:** {counts.get('PATCHED', 0)}",
        "",
        "## Findings",
        "",
        "| Priority | Asset | SAPI | Version | Gate | Status | Exposure | Owner | Evidence | Flags |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in sorted(rows, key=sort_key):
        flags = "; ".join(row["flags"])
        values = dict(row)
        values["flags"] = flags
        lines.append(
            "| {priority} | {asset} | {sapi} | {version} | {gate} | {status} | "
            "{exposure} | {owner} | {evidence_count} | {flags} |".format(**values)
        )
    lines += ["", "## Remediation", ""]
    for row in sorted(rows, key=sort_key):
        if row["priority"] in ("P0", "P1", "P2"):
            lines.append(f"- **{row['asset']}** ({row['priority']}): {row['remediation'] or 'record a remediation'}")
    lines.append("")
    return "\n".join(lines)


def build_csv(rows: list[dict], path: str) -> None:
    fields = [
        "asset", "priority", "status", "sapi", "version", "gate",
        "exposure", "owner", "remediation", "verified_at",
        "evidence_count", "interim_count", "edge_count", "flags",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for row in sorted(rows, key=sort_key):
            out = {key: row[key] for key in fields if key != "flags"}
            out["flags"] = "; ".join(row["flags"])
            writer.writerow(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate PHP2Shell JSONL findings")
    parser.add_argument("--input", required=True, help="JSONL produced by triage/inventory")
    parser.add_argument("--md", help="Write Markdown summary to this path")
    parser.add_argument("--csv", help="Write CSV to this path")
    parser.add_argument("--title", default="PHP2Shell exposure audit")
    args = parser.parse_args()

    records = load(args.input)
    if not records:
        print("no records", file=sys.stderr)
        return 2

    rows = [normalize(record) for record in records]
    markdown = build_markdown(rows, args.title)
    if args.md:
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(markdown + "\n")
    else:
        print(markdown)
    if args.csv:
        build_csv(rows, args.csv)

    counts = Counter(row["priority"] for row in rows)
    print(
        f"{len(rows)} assets: "
        + ", ".join(f"{key}={counts.get(key, 0)}" for key in ("P0", "P1", "P2", "P3", "PATCHED")),
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
