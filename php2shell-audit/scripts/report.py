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
REPRO_STATES = {
    "REPRO-OOM-DIFFERENTIAL",
    "REPRO-FATAL-BOTH",
    "REPRO-NO-EFFECT",
    "REPRO-CRASH-OBSERVED",
    "REPRO-UNAVAILABLE",
    "REPRO-INCONCLUSIVE",
}


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
    rce_state = first(record, "rce_state", default="")
    if rce_state == "RCE-CONFIRMED" and not evidence:
        flags.append("RCE confirmed without evidence")
    if rce_state == "RCE-CONFIRMED" and priority == "PATCHED":
        flags.append("RCE confirmed but marked patched")

    repro_state = first(record, "repro_state", default="").upper()
    repro_obj = record.get("repro") if isinstance(record.get("repro"), dict) else None
    if repro_obj is None:
        for item in evidence:
            if isinstance(item, dict) and item.get("type") == "lab-reproduction":
                output = item.get("output")
                if isinstance(output, dict):
                    repro_obj = output
                break
    if repro_state and repro_state not in REPRO_STATES:
        flags.append("unknown reproduction state")
    if repro_state and not repro_obj:
        flags.append("reproduction state without evidence")
    if repro_state == "REPRO-OOM-DIFFERENTIAL" and priority == "PATCHED":
        flags.append("reproduction differential but marked patched")

    repro_vulnerable = ""
    repro_patched = ""
    repro_effects: list[str] = []
    if repro_obj:
        obs = repro_obj.get("observations") if isinstance(repro_obj.get("observations"), dict) else {}
        vuln = obs.get("vulnerable") if isinstance(obs.get("vulnerable"), dict) else {}
        patched = obs.get("patched") if isinstance(obs.get("patched"), dict) else {}
        repro_vulnerable = observation_label(vuln)
        repro_patched = observation_label(patched)
        if repro_state == "REPRO-UNAVAILABLE":
            repro_vulnerable = "unavailable"
            repro_patched = "unavailable"
        effects = obs.get("execution_effects") or []
        if isinstance(effects, list):
            repro_effects = [str(effect) for effect in effects]
    repro_summary = first(record, "repro_summary", default="")
    if not repro_summary and repro_obj:
        repro_summary = (
            f"vulnerable={repro_vulnerable or 'unknown'}; "
            f"patched={repro_patched or 'unknown'}; "
            f"execution_effects={', '.join(repro_effects) or 'none'}"
        )

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
        "repro_state": repro_state,
        "repro_summary": repro_summary,
        "repro_vulnerable": repro_vulnerable,
        "repro_patched": repro_patched,
        "repro_effects": repro_effects,
        "rce_state": rce_state,
        "evidence_count": len(evidence),
        "interim_count": len(interim) if isinstance(interim, dict) else 0,
        "edge_count": len(edge) if isinstance(edge, dict) else 0,
        "flags": flags,
        "record": record,
    }


def observation_label(obs: dict) -> str:
    if obs.get("oom_detected"):
        return "OOM"
    if obs.get("crash_signal"):
        return "crash"
    if obs.get("normal_detected"):
        return "normal"
    return "no effect/unknown"


def sort_key(row: dict) -> tuple:
    return (PRIORITY_ORDER.get(row["priority"], 9), row["asset"])


def build_markdown(rows: list[dict], title: str) -> str:
    counts = Counter(row["priority"] for row in rows)
    rce_counts = Counter(row["rce_state"] for row in rows if row["rce_state"])
    repro_counts = Counter(row["repro_state"] for row in rows if row["repro_state"])
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
    ]
    if repro_counts:
        lines.append(
            "**Reproduction:** "
            + " · ".join(f"{state}={number}" for state, number in sorted(repro_counts.items()))
        )
        lines.append("")
    if rce_counts:
        lines.append(
            "**RCE:** "
            + " · ".join(f"{state}={number}" for state, number in sorted(rce_counts.items()))
        )
        lines.append("")
    lines += [
        "## Findings",
        "",
        "| Priority | Asset | SAPI | Version | Gate | Status | Repro | RCE | Exposure | Owner | Evidence | Flags |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in sorted(rows, key=sort_key):
        flags = "; ".join(row["flags"])
        values = dict(row)
        values["flags"] = flags
        values["repro"] = values.get("repro_state") or "—"
        values["rce"] = values.get("rce_state") or "—"
        lines.append(
            "| {priority} | {asset} | {sapi} | {version} | {gate} | {status} | "
            "{repro} | {rce} | {exposure} | {owner} | {evidence_count} | {flags} |".format(**values)
        )
    if repro_counts:
        lines += [
            "",
            "## Reproduction evidence",
            "",
            "| Asset | State | Vulnerable | Patched | Execution effects |",
            "|---|---|---|---|---|",
        ]
        for row in sorted(rows, key=sort_key):
            if not row["repro_state"]:
                continue
            effects = ", ".join(row["repro_effects"]) or "none"
            lines.append(
                f"| {row['asset']} | {row['repro_state']} | "
                f"{row['repro_vulnerable'] or '—'} | {row['repro_patched'] or '—'} | {effects} |"
            )
        lines += [
            "",
            "An OOM or crash differential is **not** proof of RCE. `RCE-CONFIRMED` still",
            "requires execution effects, a fresh nonce, a matching marker, and the",
            "`rce-validate.sh` artifact. See `references/lab-reproduction.md`.",
        ]
    lines += ["", "## Remediation", ""]
    for row in sorted(rows, key=sort_key):
        if row["priority"] in ("P0", "P1", "P2"):
            lines.append(f"- **{row['asset']}** ({row['priority']}): {row['remediation'] or 'record a remediation'}")
    lines.append("")
    return "\n".join(lines)


def build_csv(rows: list[dict], path: str) -> None:
    fields = [
        "asset", "priority", "status", "sapi", "version", "gate",
        "repro_state", "repro_summary", "rce_state", "exposure", "owner",
        "remediation", "verified_at", "evidence_count", "interim_count",
        "edge_count", "flags",
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
