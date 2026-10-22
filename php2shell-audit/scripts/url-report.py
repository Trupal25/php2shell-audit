#!/usr/bin/env python3
"""Render the human-readable report for a URL-based assessment.

Consumes assessment.json (produced by scripts/assess-url.sh) plus the
normalized findings.jsonl, reuses scripts/report.py for the standard
findings rendering, and adds the URL-assessment-specific sections:
scope & authorization, request evidence, chain verdict, RCE assessment
(never confirmed from URL-only collection), evidence provenance with
SHA-256 hashes, tested/not-tested boundaries, and next steps.

Usage:
  url-report.py --assessment assessment.json --findings findings.jsonl \
                --out report.md [& --csv findings.csv]

The tool also records the SHA-256 of the report and CSV it generated back
into assessment.json ("generated_sha256") so `assess-url.sh --verify DIR`
can detect tampering later.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import sys
from datetime import datetime, timezone


def load_json(path: str) -> dict:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def sha256_file(path: str) -> str:
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def esc(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def main() -> int:
    parser = argparse.ArgumentParser(description="URL assessment report builder")
    parser.add_argument("--assessment", required=True, help="assessment.json")
    parser.add_argument("--findings", required=True, help="findings.jsonl")
    parser.add_argument("--out", required=True, help="report.md path")
    parser.add_argument("--csv", help="findings.csv to hash (created separately by report.py)")
    args = parser.parse_args()

    assessment = load_json(args.assessment)
    findings_md = ""
    records = []
    try:
        # Reuse the existing fleet renderer for the standard findings table.
        here = os.path.dirname(os.path.abspath(__file__))
        spec = importlib.util.spec_from_file_location("php2shell_report", os.path.join(here, "report.py"))
        report_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(report_mod)
        with open(args.findings, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        if records:
            rows = [report_mod.normalize(record) for record in records]
            findings_md = report_mod.build_markdown(rows, "Findings (standard aggregation)")
    except Exception as exc:  # report rendering is enhancement, never fatal
        findings_md = ""
        print(f"report.py reuse skipped: {exc}", file=sys.stderr)

    a = assessment
    t = a.get("target", {})
    s = a.get("safety", {})
    ch = a.get("chain", {})
    fp = a.get("fingerprint", {})
    r = a.get("rce", {})
    c = a.get("collection", {})
    v = a.get("version_evidence", {})
    scope = t.get("scope", {})
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    scope_lines = []
    if scope.get("mode") == "lab":
        scope_lines.append(
            f"- **Lab mode** (`--lab`): non-global lab addresses are permitted "
            f"(loopback/private/link-local/metadata). Authorized scope entry: "
            f"**{scope.get('entry') or 'lab-mode (non-global address)'}**."
        )
    elif scope.get("mode") == "scope-file":
        scope_lines.append(
            f"- **Scope file** `{scope.get('scope_file')}`: target host "
            f"`{t.get('host')}` authorized via entry `{scope.get('entry')}`."
        )
    else:
        scope_lines.append(f"- Scope mode: {scope.get('mode') or 'unknown'} (see assessment.json).")
    scope_lines.append(
        "- Authorization was explicit at invocation time; this run only contacted the "
        "authorized target origin and redirect destinations that passed the same checks."
    )

    safety_lines = [
        f"- Scheme: {a.get('target', {}).get('origin', '').split('://')[0] if '://' in a.get('target', {}).get('origin', '') else '?'} (HTTP/HTTPS only)",
        "- TLS certificate verification: **ON** (never disabled)",
        "- Credentials / cookies / session tokens sent: **none**",
        "- Exploit payload sent: **none**",
        "- DNS: resolved once by the guard and **pinned** per request (`curl --resolve`), mitigating rebinding",
        "- Redirects: re-authorized per hop; https→http downgrades refused",
        f"- Bounds: connect {s.get('connect_timeout_s')}s / request {s.get('request_timeout_s')}s / "
        f"{s.get('max_redirects')} redirects / {s.get('max_bytes')} bytes per response",
    ]

    request_rows = ["| # | Method | URL | Status | curl exit | Bytes | Pin |", "|---|---|---|---|---|---|---|"]
    for h in c.get("requests", []):
        request_rows.append(
            f"| {esc(h.get('hop', ''))} | {esc(h.get('method', ''))} | {esc(h.get('url', ''))} | "
            f"{esc(h.get('status', ''))} | {esc(h.get('curl_exit', ''))} | "
            f"{esc(h.get('bytes', ''))} | {esc(h.get('pin', ''))} |"
        )

    state = a.get("state", "unknown")
    state_note = a.get("state_reason") or ""
    if state != "ok":
        outcome_lines = [
            f"**State:** `{state}`" + (f" — {state_note}" if state_note else ""),
            "",
            "Collection did not complete, so **no exposure conclusion is supported** by "
            "this run. The evidence below records what was attempted and observed.",
        ]
    else:
        outcome_lines = [
            f"**State:** `ok`",
            f"**Redirects followed:** {c.get('redirects_followed', 0)}  ",
            f"**Baseline HTTP:** {c.get('baseline_status') or '-'}  ",
            f"**Final HTTP:** {c.get('final_status') or '-'}  ",
        ]

    if v.get("version"):
        version_lines = [
            f"**Version hint:** `{v['version']}` — source: `{v.get('source')}`, "
            f"**definitive: no**. {v.get('note', '')}",
        ]
        if v.get("server_header") or v.get("x_powered_by"):
            version_lines.append(
                f"- `Server:` {v.get('server_header') or '(absent)'}  "
                f"`X-Powered-By:` {v.get('x_powered_by') or '(absent)'}"
            )
    else:
        version_lines = [
            "**Version:** not exposed over HTTP (or **no PHP signal** observed). "
            + (v.get("note", "") or ""),
        ]

    rce_state = r.get("state") or ""
    if rce_state:
        rce_lines = [
            f"**State:** `{rce_state}`",
            "",
            r.get("note", ""),
            "",
            "The state was produced by `scripts/rce-validate.sh` from a separate, "
            "authorized artifact (`rce.json`); the URL-only collection in this run sent "
            "no execution trigger itself.",
        ]
    else:
        rce_lines = [
            f"**State:** not established",
            "",
            r.get("note", ""),
        ]
    rce_lines += [
        "",
        "State semantics (from `scripts/rce-validate.sh`, unchanged):",
        "",
        "| State | Meaning |",
        "|---|---|",
        "| `RCE-CONFIRMED` | Only when the validator's full, evidence-backed execution requirements are genuinely satisfied. |",
        "| `RCE-BLOCKED` | Only when reliable evidence establishes the applicable blocking condition. |",
        "| `RCE-NOT-REPRODUCED` | The defined test did not reproduce the claimed execution behavior. |",
        "| `RCE-INCONCLUSIVE` | Available evidence cannot establish the result. |",
        "",
        "A URL-only assessment sends no execution trigger: it **cannot** legitimately "
        "produce `RCE-CONFIRMED`, no matter what HTTP banners say.",
    ]

    pre = ch.get("preconditions", {})
    if pre:
        labels = {
            "version_below_gate": "PHP below patch gate",
            "web_sapi": "Web SAPI reachable",
            "upload_progress_on": "session.upload_progress enabled",
            "memory_limit_finite": "finite memory_limit (OOM window)",
            "multipart_unlimited": "multipart parts unlimited",
            "backtraces_on": "8.5 fatal_error_backtraces=1",
            "edge_accepts_key": "edge accepts oversized key",
        }
        friendly = {
            "present": "CONFIRMED PRESENT",
            "absent": "confirmed absent",
            "unknown": "unknown",
            "open": "open (no patch gate)",
            "n/a": "n/a",
        }
        chain_rows = ["| Precondition | Status |", "|---|---|"]
        for key, status in pre.items():
            chain_rows.append(f"| {labels.get(key, key)} | {friendly.get(status, esc(status))} |")
        chain_md = (
            f"**Verdict:** `{ch.get('decision', 'UNKNOWN')}`  "
            f"**Version:** {ch.get('version', 'unknown')} (gate {ch.get('gate', 'none')})  "
            f"**SAPI:** {ch.get('sapi', 'unknown')}  "
            f"**Version proof:** {ch.get('version_proof', 'none')}\n\n"
            + "\n".join(chain_rows)
            + (f"\n\n{ch.get('proof_note', '')}" if ch.get("proof_note") else "")
        )
    else:
        chain_md = f"**Verdict:** `{ch.get('decision', 'UNKNOWN')}` (no precondition evidence collected)"

    hashes = a.get("artifact_hashes", {}).get("sha256", {})
    hash_rows = ["| Artifact | SHA-256 |", "|---|---|"]
    for name in sorted(hashes):
        hash_rows.append(f"| `{esc(name)}` | `{hashes[name]}` |")

    tested_lines = [
        f"- Safe HTTP collection from `{t.get('origin', '')}` with DNS pinning and "
        "re-authorized redirects",
        "- One bounded long-key edge-conformance POST (2048-byte key; a control probe, "
        "not an exploit payload)" if c.get("edge_result", "SKIPPED") != "SKIPPED" else
        "- (Edge probe skipped because GET collection did not complete)",
        "- Precondition-chain verdict from `scripts/chain.sh` on the derived evidence",
        "- Optional RCE evidence validation via `scripts/rce-validate.sh` "
        "(only when `--rce-evidence` was supplied)",
    ]

    limits = a.get("limits", [])
    limitation_lines = []
    if a.get("not_tested"):
        pass
    limitation_lines += [f"- {item}" for item in a.get("limitations", [])]
    if limits:
        limitation_lines += [f"- Limit reached: **{esc(l['type'])}** — {esc(l.get('note', ''))}" for l in limits]
    if not a.get("consistency", {}).get("ok", True):
        limitation_lines.append(
            "- **Consistency problem detected:** " + "; ".join(a["consistency"].get("reasons", []))
        )

    lines = [
        f"# PHP2Shell remote URL assessment — {t.get('asset', 'unknown')}",
        "",
        f"Generated: {now}  ",
        f"Tool: php2shell-audit {a.get('tool', {}).get('version', '?')} "
        f"(`scripts/assess-url.sh`, schema {a.get('schema', '?')})  ",
        f"Target: `{t.get('url', '')}`  ",
        f"Origin: `{t.get('origin', '')}`  ",
        f"Exposure class: {t.get('exposure', 'unknown')}",
        "",
        "## Scope & authorization",
        "",
        *scope_lines,
        "",
        "## Safety model applied",
        "",
        *safety_lines,
        "",
        "## Outcome",
        "",
        *outcome_lines,
        "",
        "## Version evidence (hint only)",
        "",
        *version_lines,
        "",
        f"**PHP signal:** {fp.get('php', 'unknown')} · "
        f"**SAPI hint:** {fp.get('sapi_hint', 'unknown')} "
        f"({fp.get('confidence', 'low')} confidence) · "
        f"**Header hint decision:** `{fp.get('decision', 'UNKNOWN')}` — "
        f"{fp.get('reason', '')}",
        "",
        "## Requests observed",
        "",
        *request_rows,
        "",
        "## Chain verdict",
        "",
        chain_md,
        "",
        "## RCE assessment",
        "",
        *rce_lines,
        "",
        "## Evidence provenance",
        "",
        "Raw captures, derived artifacts, and their hashes:",
        "",
        *hash_rows,
        "",
        f"Integrity: re-check at any time with `assess-url.sh --verify <this directory>` "
        "(exit 5 on tampering or contradiction).",
        "",
        "## What was tested",
        "",
        *tested_lines,
        "",
        "## What was NOT tested",
        "",
        *[f"- {item}" for item in a.get("not_tested", [])],
        "",
        "## Recommended next steps",
        "",
        *[f"{i+1}. {step}" for i, step in enumerate(a.get("next_steps", []))],
        "",
        "## Limitations & confidence",
        "",
        *limitation_lines,
        "",
        "Confidence is capped by the limits above: HTTP-only hints cannot establish a "
        "patch state, and this run does not claim execution of any kind.",
        "",
    ]

    if findings_md:
        lines += [
            "---",
            "",
            findings_md.rstrip(),
            "",
        ]

    lines += [
        "---",
        "",
        "Remote URL assessment and Docker lab reproduction are distinct: a URL verdict "
        "never substitutes for the bounded OOM differential evidence from "
        "`scripts/lab-repro.sh`, and neither produces `RCE-CONFIRMED` by itself.",
        "",
    ]

    markdown = "\n".join(lines)

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(markdown)
    if not markdown.endswith("\n"):
        with open(args.out, "a", encoding="utf-8") as fh:
            fh.write("\n")

    # Record generated-artifact hashes back into assessment.json so --verify
    # can detect later tampering of the rendered outputs.
    gen = {}
    gen["report.md"] = sha256_file(args.out)
    if args.csv and os.path.isfile(args.csv):
        gen["findings.csv"] = sha256_file(args.csv)
    a["generated_sha256"] = gen
    with open(args.assessment, "w", encoding="utf-8") as fh:
        json.dump(a, fh, ensure_ascii=False, indent=2, sort_keys=True)
        fh.write("\n")

    print(f"report.md written: {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
