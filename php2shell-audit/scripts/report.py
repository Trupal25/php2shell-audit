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
IMPACT_ORDER = {
    "inconclusive": 0,
    "suspected-exposure": 1,
    "crash-oom": 2,
    "memory-safety-failure": 3,
    "memory-disclosure": 4,
    "demonstrated-code-execution": 5,
}
IMPACTS = tuple(IMPACT_ORDER)
STRONG_IMPACTS = {
    "crash-oom",
    "memory-safety-failure",
    "memory-disclosure",
    "demonstrated-code-execution",
}
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
    if not rce_state:
        for item in evidence:
            if not isinstance(item, dict):
                continue
            output = item.get("output")
            if not isinstance(output, dict):
                continue
            if item.get("type") == "rce-validation" and output.get("state"):
                rce_state = str(output.get("state"))
                break
            if item.get("type") == "validation-module-run":
                embedded = output.get("rce_validation")
                if isinstance(embedded, dict) and embedded.get("state"):
                    state = str(embedded.get("state"))
                    module_cls = output.get("classification")
                    corr = (
                        module_cls.get("corroboration")
                        if isinstance(module_cls, dict)
                        and isinstance(module_cls.get("corroboration"), dict)
                        else {}
                    )
                    if state == "RCE-CONFIRMED" and corr.get("control_marker_in_target"):
                        state = "RCE-INCONCLUSIVE"
                    rce_state = state
                    break
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

    # Validation-module evidence. The record's impact fields are authoritative;
    # older records fall back to the same conservative derivation used by
    # run-audit.sh.
    module_run = record.get("module_run") if isinstance(record.get("module_run"), dict) else None
    if module_run is None:
        for item in evidence:
            if isinstance(item, dict) and item.get("type") == "validation-module-run":
                output = item.get("output")
                if isinstance(output, dict):
                    module_run = output
                break
    module_run = module_run or {}
    module_cls = module_run.get("classification") if isinstance(module_run.get("classification"), dict) else {}
    module = module_run.get("module") if isinstance(module_run.get("module"), dict) else {}
    module_id = first(record, "module_id", default="") or str(module.get("id") or "")
    module_synthetic = bool(record.get("validation_synthetic") or module_run.get("synthetic") or module_cls.get("synthetic"))
    module_state = str(module_run.get("state") or record.get("module_state") or "")
    validation_impact = first(record, "validation_impact", default="") or str(module_cls.get("impact") or "")
    validation_impact = validation_impact if validation_impact in IMPACT_ORDER else ""
    validation_confidence = first(record, "validation_confidence", default="") or str(module_cls.get("confidence") or "")
    checks = module_cls.get("checks") if isinstance(module_cls.get("checks"), dict) else {}
    arts = checks.get("artifacts_verified") if isinstance(checks.get("artifacts_verified"), dict) else {}
    try:
        declared_arts = int(arts.get("declared") or 0)
        verified_arts = int(arts.get("verified") or 0)
    except (TypeError, ValueError):
        declared_arts, verified_arts = 0, 0
    corr = module_cls.get("corroboration") if isinstance(module_cls.get("corroboration"), dict) else {}
    module_verified = bool(corr.get("execution_corroborated")) or (
        declared_arts > 0 and verified_arts == declared_arts
    )
    module_negative = module_cls.get("negative_controls") if isinstance(module_cls.get("negative_controls"), dict) else {}
    module_reproduction = module_cls.get("reproduction_steps") if isinstance(module_cls.get("reproduction_steps"), list) else []
    module_env = module_cls.get("environment_dependencies") if isinstance(module_cls.get("environment_dependencies"), list) else []
    module_limitations = module_cls.get("limitations") if isinstance(module_cls.get("limitations"), list) else []
    module_evidence_refs = module_cls.get("evidence_refs") if isinstance(module_cls.get("evidence_refs"), list) else []
    module_obs = module_run.get("harness_observations") if isinstance(module_run.get("harness_observations"), dict) else {}

    impact = first(record, "impact", default="").lower()
    if impact not in IMPACT_ORDER:
        if rce_state == "RCE-CONFIRMED":
            impact = "demonstrated-code-execution"
        elif repro_state in ("REPRO-OOM-DIFFERENTIAL", "REPRO-CRASH-OBSERVED"):
            impact = "crash-oom"
        elif priority == "PATCHED":
            impact = "inconclusive"
        elif first(record, "status") == "vulnerable":
            impact = "suspected-exposure"
        else:
            impact = "inconclusive"
    impact_confidence = first(record, "impact_confidence", default="")
    if not impact_confidence:
        impact_confidence = {
            "demonstrated-code-execution": "corroborated",
            "memory-disclosure": "corroborated",
            "memory-safety-failure": "observed",
            "crash-oom": "observed",
            "suspected-exposure": "exposure-only",
            "inconclusive": "insufficient",
        }.get(impact, "insufficient")
    impact_basis = record.get("impact_basis") if isinstance(record.get("impact_basis"), list) else []
    impact_basis = [str(item) for item in impact_basis]
    impact_applicable = record.get("impact_applicable", True)
    if isinstance(impact_applicable, str):
        impact_applicable = impact_applicable.lower() not in ("false", "0", "no", "")
    impact_applicable = bool(impact_applicable)

    if impact == "demonstrated-code-execution" and rce_state != "RCE-CONFIRMED":
        flags.append("execution impact without RCE-CONFIRMED")
    if module_synthetic:
        flags.append("synthetic validation module (not evidence)")
        if validation_impact == "demonstrated-code-execution":
            flags.append("synthetic fixture execution claim rejected")
    if validation_impact in STRONG_IMPACTS and not module_verified and not module_synthetic:
        flags.append("validation impact without verified artifacts")
    if module_state in ("failed", "timeout", "unavailable") and validation_impact in STRONG_IMPACTS:
        flags.append("module did not complete but validation impact claimed")
    if priority == "PATCHED" and validation_impact in STRONG_IMPACTS:
        flags.append("lab validation applies to vulnerable build, not this patched target")
    if impact in STRONG_IMPACTS and priority == "PATCHED":
        flags.append("impact claim but marked patched")

    validation_summary = first(record, "validation_summary", default="")
    if not validation_summary:
        if module_id:
            validation_summary = f"{module_id}: {validation_impact or 'inconclusive'} ({validation_confidence or 'insufficient'})"
            if module_synthetic:
                validation_summary += " [synthetic, not evidence]"
            elif not module_verified and validation_impact in STRONG_IMPACTS:
                validation_summary += " [artifacts unverified]"
        else:
            validation_summary = "no validation module executed"

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
        "impact": impact,
        "impact_confidence": impact_confidence,
        "impact_applicable": impact_applicable,
        "impact_basis": impact_basis,
        "module_id": module_id,
        "module_state": module_state,
        "module_synthetic": module_synthetic,
        "module_verified": module_verified,
        "validation_impact": validation_impact,
        "validation_confidence": validation_confidence,
        "validation_synthetic": module_synthetic,
        "validation_summary": validation_summary,
        "module_run": module_run,
        "module_cls": module_cls,
        "module_negative": module_negative,
        "module_reproduction": module_reproduction,
        "module_env": module_env,
        "module_limitations": module_limitations,
        "module_evidence_refs": module_evidence_refs,
        "module_obs": module_obs,
        "module_targets": module_run.get("targets") if isinstance(module_run.get("targets"), dict) else {},
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


def md_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip() or "—"


def sort_key(row: dict) -> tuple:
    return (PRIORITY_ORDER.get(row["priority"], 9), row["asset"])


def build_markdown(rows: list[dict], title: str) -> str:
    counts = Counter(row["priority"] for row in rows)
    impact_counts = Counter(row["impact"] for row in rows)
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
    if impact_counts:
        lines.append(
            "**Impact:** "
            + " · ".join(
                f"{impact}={number}"
                for impact, number in sorted(
                    impact_counts.items(), key=lambda item: IMPACT_ORDER.get(item[0], 9)
                )
            )
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
        "| Priority | Asset | SAPI | Version | Gate | Status | Impact | Validation | Repro | RCE | Exposure | Owner | Evidence | Flags |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in sorted(rows, key=sort_key):
        flags = "; ".join(row["flags"])
        values = dict(row)
        values["flags"] = flags
        values["repro"] = values.get("repro_state") or "—"
        values["rce"] = values.get("rce_state") or "—"
        values["impact"] = values.get("impact") or "inconclusive"
        values["validation"] = md_cell(values.get("validation_summary") or "—")
        lines.append(
            "| {priority} | {asset} | {sapi} | {version} | {gate} | {status} | "
            "{impact} | {validation} | {repro} | {rce} | {exposure} | {owner} | {evidence_count} | {flags} |".format(**values)
        )

    rows_with_module = [row for row in sorted(rows, key=sort_key) if row.get("module_run")]
    lines += ["", "## Validation and impact", ""]
    if not rows_with_module:
        lines.append(
            "No validation module was executed. Impacts are derived only from exposure, "
            "reproduction, and RCE-validator evidence; no dynamic execution is claimed."
        )
    else:
        lines += [
            "| Asset | Target impact | Validation impact | Module | Synthetic | Verified | State | Negative control |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for row in rows_with_module:
            neg = row.get("module_negative") or {}
            neg_bits: list[str] = []
            if "patched_oom" in neg:
                neg_bits.append("patched OOM=" + ("yes" if neg.get("patched_oom") else "no"))
            if "patched_normal_response" in neg:
                neg_bits.append(
                    "patched normal=" + ("yes" if neg.get("patched_normal_response") else "no")
                )
            if "patched_disclosure_canary" in neg:
                neg_bits.append(
                    "patched canary=" + ("yes" if neg.get("patched_disclosure_canary") else "no")
                )
            lines.append(
                f"| {md_cell(row['asset'])} | {row['impact']} | {row['validation_impact'] or '—'} | "
                f"{md_cell(row['module_id'] or '—')} | {'yes' if row['module_synthetic'] else 'no'} | "
                f"{'yes' if row['module_verified'] else 'no'} | {md_cell(row['module_state'] or '—')} | "
                f"{md_cell('; '.join(neg_bits) or '—')} |"
            )

        for row in rows_with_module:
            lines += ["", f"### {row['asset']} — {row['impact']}", ""]
            lines.append(
                f"**Target impact:** {row['impact']} (confidence: {row['impact_confidence']}; "
                f"applicable: {'yes' if row['impact_applicable'] else 'no'})"
            )
            if row.get("impact_basis"):
                lines += ["", "**Basis:**"]
                for item in row["impact_basis"]:
                    lines.append(f"- {item}")
            lines += [
                "",
                f"**Validation module:** `{row['module_id'] or 'unknown'}` "
                f"(state: {row['module_state'] or 'unknown'}; "
                f"synthetic: {'yes' if row['module_synthetic'] else 'no'}; "
                f"artifacts verified: {'yes' if row['module_verified'] else 'no'})",
                "",
                f"**Demonstrated impact:** lab validation classified `{row['validation_impact'] or 'inconclusive'}` "
                f"with confidence `{row['validation_confidence'] or 'insufficient'}`. "
                f"The target impact is `{row['impact']}`.",
            ]
            if row.get("module_reproduction"):
                lines += ["", "**Reproduction steps:**"]
                for index, step in enumerate(row["module_reproduction"], 1):
                    lines.append(f"{index}. {step}")
            if row.get("module_evidence_refs"):
                lines += ["", "**Evidence references:**"]
                for ref in row["module_evidence_refs"]:
                    lines.append(f"- `{ref}`")
            if row.get("module_negative"):
                lines += ["", "**Negative controls:**"]
                for key, value in row["module_negative"].items():
                    lines.append(f"- `{key}`: {value}")
            if row.get("module_env"):
                lines += ["", "**Environmental dependencies:**"]
                for item in row["module_env"]:
                    lines.append(f"- {item}")
            if row.get("module_limitations"):
                lines += ["", "**Limitations:**"]
                for item in row["module_limitations"]:
                    lines.append(f"- {item}")

    lines += [
        "",
        "**Interpretation boundary:** an OOM or crash is not memory corruption or code "
        "execution; a synthetic fixture is never evidence; "
        "`demonstrated-code-execution` requires a corroborated target marker and an "
        "`RCE-CONFIRMED` validator result.",
    ]
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
        "impact", "impact_confidence", "impact_applicable",
        "validation_impact", "validation_confidence", "validation_synthetic",
        "module_id", "module_state", "validation_summary",
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
