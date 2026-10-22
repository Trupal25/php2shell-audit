#!/usr/bin/env python3
"""Classify validation-module evidence into a conservative impact taxonomy.

The classifier never trusts a module's self-reported JSON on its own. It reads
the raw artifacts and the harness provenance, then applies fixed promotion rules:

  suspected-exposure < crash-oom < memory-safety-failure
  < memory-disclosure < demonstrated-code-execution

Any missing, contradictory, synthetic, or uncorroborated evidence is
`inconclusive`. OOMs and crashes are never promoted to code execution.

Usage:
  impact-classify.py --validate-manifest DIR [--allow-synthetic] [--json]
  impact-classify.py --run module-run.json [--rce rce.json] [--marker FILE]
                     [--canary VALUE] [--out classification.json] [--json]
  impact-classify.py --result module-result.json [--provenance provenance.json]
                     [--result-dir DIR] ... [--out FILE] [--json]
  impact-classify.py --context context.json [--out FILE] [--json]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA = 1
TAXONOMY = (
    "suspected-exposure",
    "crash-oom",
    "memory-safety-failure",
    "memory-disclosure",
    "demonstrated-code-execution",
    "inconclusive",
)
ALLOWED_INTERPRETERS = {"php", "python", "python3", "sh", "bash", "node", "perl", "ruby"}
GATES = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
WEB_SAPIS = ("mod_php", "frankenphp", "fpm", "lsapi", "cgi", "fastcgi")
OOM_RE = re.compile(r"Allowed memory size of \d+ bytes exhausted", re.IGNORECASE)
MEMSAFETY_RE = re.compile(
    r"AddressSanitizer|heap-use-after-free|heap-buffer-overflow|"
    r"zend_mm_heap corrupted|double free|invalid free|"
    r"segmentation fault|core dumped|heap corruption|"
    r"exit signal (?:Segmentation fault|Aborted|Bus error)",
    re.IGNORECASE,
)
HEX64_RE = re.compile(r"[A-Fa-f0-9]{64}")


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_json(path: str | None) -> Any:
    if not path:
        return None
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def safe_rel_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    if value.startswith("/") or value.startswith("\\"):
        return False
    parts = value.replace("\\", "/").split("/")
    return all(part not in ("", ".", "..") for part in parts)


def version_tuple(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in str(value or "").split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def gate_for(version: str) -> str | None:
    return GATES.get(".".join(str(version or "").split(".")[:2]))


def version_meets_gate(version: str) -> bool:
    gate = gate_for(version)
    return bool(gate) and version_tuple(version) >= version_tuple(gate)


def text_of(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def classify_result(
    *,
    result: dict | None,
    provenance: dict | None,
    result_dir: str | None,
    rce: dict | None,
    marker: str | None,
    canary: str | None,
    context: dict | None,
    out_path: str | None,
) -> dict:
    checks: dict[str, Any] = {}
    reasons: list[str] = []
    basis: list[str] = []
    limitations: list[str] = []

    result = result if isinstance(result, dict) else {}
    provenance = provenance if isinstance(provenance, dict) else {}
    context = context if isinstance(context, dict) else {}

    asset = (
        str(result.get("asset") or provenance.get("asset") or context.get("asset") or "unknown")
    )
    module = result.get("module") if isinstance(result.get("module"), dict) else {}
    if not module and isinstance(provenance.get("module"), dict):
        module = provenance["module"]
    module_id = str(module.get("id") or provenance.get("module", {}).get("id") or "")
    synthetic = bool(
        module.get("synthetic")
        or result.get("synthetic")
        or provenance.get("synthetic")
        or (result.get("claims") or {}).get("synthetic")
    )

    # ---- structural validation -------------------------------------------
    kind = result.get("kind")
    schema = result.get("schema")
    checks["result_kind"] = {"ok": kind == "validation-module-result", "value": kind}
    checks["result_schema"] = {"ok": schema == SCHEMA, "value": schema}
    if result and kind != "validation-module-result":
        reasons.append("module result kind is not 'validation-module-result'")
    if result and schema != SCHEMA:
        reasons.append("module result schema is not 1")

    if result and module_id:
        manifest_id = str(provenance.get("module", {}).get("id") or "")
        if manifest_id and manifest_id != module_id:
            reasons.append(
                f"result module id '{module_id}' does not match manifest '{manifest_id}'"
            )
    if result and not module_id:
        reasons.append("module result has no module.id")

    status = str(result.get("status") or "").strip().lower()
    checks["module_status"] = {"ok": status == "completed", "value": status}
    if result and status != "completed":
        reasons.append(f"module status is '{status or 'missing'}'; only completed runs can support impact")

    result_asset = str(result.get("asset") or "")
    if result and provenance.get("asset") and result_asset and result_asset != str(provenance["asset"]):
        reasons.append(
            f"result asset '{result_asset}' does not match harness asset '{provenance['asset']}'"
        )
    result_nonce = str(result.get("nonce") or "")
    prov_nonce = str(provenance.get("nonce") or "")
    if result and prov_nonce and result_nonce and result_nonce != prov_nonce:
        reasons.append("result nonce does not match the harness nonce")

    # ---- artifact verification -------------------------------------------
    artifacts = result.get("artifacts") if isinstance(result.get("artifacts"), list) else []
    verified_artifacts: list[dict] = []
    artifact_bytes: dict[str, bytes] = {}
    for item in artifacts:
        if not isinstance(item, dict):
            reasons.append("artifact entry is not an object")
            continue
        rel = item.get("path")
        if not safe_rel_path(rel):
            reasons.append(f"artifact path is not safe: {rel!r}")
            continue
        declared = str(item.get("sha256") or "")
        if not HEX64_RE.fullmatch(declared):
            reasons.append(f"artifact {rel} has no 64-hex sha256")
            continue
        if result_dir:
            absolute = os.path.join(result_dir, rel)
            if not os.path.isfile(absolute):
                reasons.append(f"artifact is missing: {rel}")
                continue
            with open(absolute, "rb") as fh:
                data = fh.read()
            actual = sha256_bytes(data)
            if actual != declared.lower():
                reasons.append(f"artifact hash mismatch: {rel}")
                continue
            artifact_bytes[rel] = data
            verified_artifacts.append({**item, "verified": True})
        else:
            verified_artifacts.append({**item, "verified": False})
    checks["artifacts_verified"] = {
        "declared": len(artifacts),
        "verified": sum(1 for a in verified_artifacts if a.get("verified")),
        "result_dir": bool(result_dir),
    }

    def artifact_for(role: str, kind: str | None = None) -> tuple[dict | None, bytes | None]:
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            if str(item.get("role") or "") != role:
                continue
            if kind and str(item.get("kind") or "") != kind:
                continue
            rel = item.get("path")
            if rel in artifact_bytes:
                return item, artifact_bytes[rel]
        return None, None

    def all_artifacts_of_kind(kind: str) -> list[tuple[dict, bytes]]:
        found = []
        for item in artifacts:
            if isinstance(item, dict) and str(item.get("kind") or "") == kind:
                rel = item.get("path")
                if rel in artifact_bytes:
                    found.append((item, artifact_bytes[rel]))
        return found

    # ---- harness observations --------------------------------------------
    obs = provenance.get("harness_observations")
    obs = obs if isinstance(obs, dict) else {}
    v_obs = obs.get("vulnerable") if isinstance(obs.get("vulnerable"), dict) else {}
    p_obs = obs.get("patched") if isinstance(obs.get("patched"), dict) else {}

    v_oom_log = bool(v_obs.get("oom_in_log"))
    p_oom_log = bool(p_obs.get("oom_in_log"))
    v_crash_log = bool(v_obs.get("crash_signal_in_log"))
    p_crash_log = bool(p_obs.get("crash_signal_in_log"))
    v_running = v_obs.get("running_after")
    p_running = p_obs.get("running_after")

    v_resp_art, v_resp = artifact_for("vulnerable", "response")
    p_resp_art, p_resp = artifact_for("patched", "response")
    v_oom_resp = bool(v_resp and OOM_RE.search(v_resp.decode("utf-8", "replace")))
    p_oom_resp = bool(p_resp and OOM_RE.search(p_resp.decode("utf-8", "replace")))
    v_normal = False
    p_normal = False
    for resp, label in ((v_resp, "vulnerable"), (p_resp, "patched")):
        if not resp:
            continue
        try:
            parsed = json.loads(resp.decode("utf-8", "replace"))
            normal = isinstance(parsed, dict) and parsed.get("probe") == "lab-reproduction"
        except (ValueError, TypeError):
            normal = False
        if label == "vulnerable":
            v_normal = normal
        else:
            p_normal = normal

    v_oom = v_oom_log or v_oom_resp
    p_oom = p_oom_log or p_oom_resp
    v_crash = v_crash_log
    p_crash = p_crash_log
    differential_oom = bool(v_oom and not p_oom)
    differential_crash = bool(v_crash and not p_crash)

    checks["oom"] = {
        "vulnerable": v_oom,
        "patched": p_oom,
        "source": {
            "vulnerable": "harness_log" if v_oom_log else ("response_artifact" if v_oom_resp else "none"),
            "patched": "harness_log" if p_oom_log else ("response_artifact" if p_oom_resp else "none"),
        },
    }
    checks["normal_response"] = {"vulnerable": v_normal, "patched": p_normal}
    checks["crash"] = {"vulnerable": v_crash, "patched": p_crash}

    # Memory-safety signals are read from target logs and response artifacts.
    def memsafety_text(role: str, log: dict, response: bytes | None) -> str:
        pieces = [text_of(log), response.decode("utf-8", "replace") if response else ""]
        for item, data in all_artifacts_of_kind("target-log"):
            if str(item.get("role") or "") == role:
                pieces.append(data.decode("utf-8", "replace"))
        return "\n".join(pieces)

    v_mem_text = memsafety_text("vulnerable", v_obs, v_resp)
    p_mem_text = memsafety_text("patched", p_obs, p_resp)
    v_memsafety = bool(MEMSAFETY_RE.search(v_mem_text))
    p_memsafety = bool(MEMSAFETY_RE.search(p_mem_text))
    checks["memory_safety"] = {"vulnerable": v_memsafety, "patched": p_memsafety}

    # Disclosure: require the harness canary in a vulnerable memory-dump and
    # its absence from the patched control dump.
    canary_bytes = canary.encode() if canary and len(canary) >= 8 else b""
    v_dump = artifact_for("vulnerable", "memory-dump")[1]
    p_dump = artifact_for("patched", "memory-dump")[1]
    v_canary = bool(canary_bytes and v_dump and canary_bytes in v_dump)
    p_canary = bool(canary_bytes and p_dump and canary_bytes in p_dump)
    checks["disclosure"] = {
        "canary_supplied": bool(canary_bytes),
        "vulnerable_canary": v_canary,
        "patched_canary": p_canary,
        "vulnerable_dump": bool(v_dump),
        "patched_dump": bool(p_dump),
    }

    # Execution: a separate validator result plus an independently retrieved
    # marker in the target. A self-reported effect list is not enough.
    rce_state = ""
    if isinstance(rce, dict):
        rce_state = str(rce.get("state") or "")
    if not rce_state:
        rce_state = str(result.get("rce_state") or provenance.get("rce_state") or "")
    claims = result.get("claims") if isinstance(result.get("claims"), dict) else {}
    effects = claims.get("execution_effects")
    effects = effects if isinstance(effects, list) else []
    corr = provenance.get("corroboration") if isinstance(provenance.get("corroboration"), dict) else {}
    marker_in_target = bool(corr.get("marker_in_target"))
    control_marker_in_target = bool(corr.get("control_marker_in_target"))
    marker_sha = str(corr.get("marker_sha256") or "")
    marker_ok = False
    if marker and os.path.isfile(marker):
        actual = sha256_file(marker)
        marker_ok = bool(marker_sha) and actual.lower() == marker_sha.lower()
    checks["execution"] = {
        "rce_state": rce_state,
        "execution_effects": effects,
        "marker_in_target": marker_in_target,
        "control_marker_in_target": control_marker_in_target,
        "marker_file_supplied": bool(marker),
        "marker_hash_matches": marker_ok,
    }
    execution_corroborated = bool(
        not synthetic
        and status == "completed"
        and rce_state == "RCE-CONFIRMED"
        and effects
        and marker_in_target
        and not control_marker_in_target
        and (not marker or marker_ok)
    )
    if rce_state == "RCE-CONFIRMED" and not execution_corroborated:
        reasons.append(
            "RCE-CONFIRMED is not corroborated by a target marker and matching marker hash"
        )
    if control_marker_in_target:
        reasons.append(
            "the patched control also produced the execution marker; the effect is not differential"
        )

    # ---- target applicability --------------------------------------------
    target_version = ""
    targets = provenance.get("targets") if isinstance(provenance.get("targets"), dict) else {}
    v_target = targets.get("vulnerable") if isinstance(targets.get("vulnerable"), dict) else {}
    result_targets = result.get("targets") if isinstance(result.get("targets"), dict) else {}
    result_v_target = result_targets.get("vulnerable") if isinstance(result_targets.get("vulnerable"), dict) else {}
    target_version = str(
        v_target.get("version")
        or result_v_target.get("php_version")
        or context.get("version")
        or ""
    )
    sapi = str(context.get("sapi") or v_target.get("sapi") or "")
    applicable = True
    if target_version and version_meets_gate(target_version):
        applicable = False
        reasons.append(f"target version {target_version} meets the patch gate")
    if context and sapi and not any(part in sapi.lower() for part in WEB_SAPIS):
        applicable = False
        reasons.append(f"SAPI '{sapi}' is not a web SAPI")

    # ---- decide -----------------------------------------------------------
    impact = "inconclusive"
    confidence = "insufficient"

    if synthetic:
        impact = "inconclusive"
        confidence = "insufficient"
        basis.append("synthetic fixture; synthetic results are never evidence of demonstrated impact")
        limitations.append(
            "Synthetic module result. It exercises the interface/classifier only and was not run against a target."
        )
    elif context and not result:
        decision = str(context.get("decision") or "").upper()
        if not applicable:
            impact = "inconclusive"
            confidence = "insufficient"
            basis.append("exploitation path is not applicable to this target")
        elif decision == "CHAIN-OPEN":
            impact = "suspected-exposure"
            confidence = "exposure-only"
            basis.append("below-gate web SAPI is reachable, but no validation module was run")
        else:
            impact = "inconclusive"
            confidence = "insufficient"
            basis.append("no validation module was run and the chain is not open")
    elif not result:
        impact = "inconclusive"
        confidence = "insufficient"
        basis.append("no module result was available")
    elif status not in ("", "completed") or (kind and kind != "validation-module-result"):
        impact = "inconclusive"
        confidence = "insufficient"
        basis.append("module did not complete with a valid result")
    elif execution_corroborated:
        impact = "demonstrated-code-execution"
        confidence = "corroborated"
        basis.append("RCE validator state is RCE-CONFIRMED")
        basis.append("marker was independently retrieved from the target container")
        basis.append("execution_effects is non-empty")
    elif v_canary and not p_canary:
        impact = "memory-disclosure"
        confidence = "corroborated"
        basis.append("harness canary was found in the vulnerable memory dump")
        basis.append("the patched control dump did not contain the canary")
    elif v_memsafety and not p_memsafety:
        impact = "memory-safety-failure"
        confidence = "observed"
        basis.append("a sanitizer/heap-corruption/crash signal was observed in the vulnerable target only")
    elif (differential_oom or differential_crash) and applicable:
        impact = "crash-oom"
        confidence = "observed"
        if differential_oom:
            basis.append("vulnerable target exhausted memory; patched control did not")
        if differential_crash:
            basis.append("vulnerable target showed a crash signal; patched control did not")
    else:
        impact = "inconclusive"
        confidence = "insufficient"
        if not applicable:
            basis.append("exploitation path is not applicable to this target")
        elif v_oom or p_oom or v_crash or p_crash:
            basis.append("the effect was not differential or was not independently corroborated")
        else:
            basis.append("no corroborated impact signal")

    if impact == "crash-oom":
        limitations.append(
            "An OOM or worker crash is a denial-of-service/availability observation; it is not memory disclosure or code execution."
        )
    if impact == "memory-safety-failure":
        limitations.append(
            "A crash/heap signal is not proof of memory disclosure or code execution."
        )
    if impact == "memory-disclosure":
        limitations.append(
            "Disclosure is limited to the corroborated bytes; it does not imply code execution."
        )
    if impact == "demonstrated-code-execution":
        limitations.append(
            "Code execution is limited to the evidence bundle's nonce, marker, and observed effects."
        )

    # Merge module-reported limitations; never drop the classifier's own.
    for item in result.get("limitations") or []:
        if isinstance(item, str) and item not in limitations:
            limitations.append(item)

    negative_controls = {
        "patched_oom": p_oom,
        "patched_crash": p_crash,
        "patched_memory_safety": p_memsafety,
        "patched_disclosure_canary": p_canary,
        "patched_execution_marker": control_marker_in_target,
        "patched_normal_response": p_normal,
        "patched_running_after": p_running,
    }

    # Reproduction steps and environment dependencies.
    invocation = provenance.get("invocation") if isinstance(provenance.get("invocation"), dict) else {}
    argv = invocation.get("argv") if isinstance(invocation.get("argv"), list) else []
    reproduction_steps: list[str] = []
    if argv:
        reproduction_steps.append("Invocation: `" + shlex.join(str(a) for a in argv) + "`")
    for role in ("vulnerable", "patched"):
        image = (targets.get(role) or {}).get("image") if isinstance(targets.get(role), dict) else ""
        if image:
            reproduction_steps.append(f"`docker pull {image}` (the harness starts it on an internal network).")
    if module_id:
        reproduction_steps.append(
            f"Re-run the module: `bash scripts/module-run.sh --module <path-to-{module_id}> --asset {asset} --out <dir>`."
        )
    reproduction_steps.append(
        "Classify the run: `python3 scripts/impact-classify.py --run <dir>/module-run.json --out <dir>/classification.json`."
    )

    env_deps = []
    if invocation.get("docker_version"):
        env_deps.append(f"Docker {invocation['docker_version']} on {invocation.get('host', 'unknown host')}")
    for role in ("vulnerable", "patched"):
        target = targets.get(role) if isinstance(targets.get(role), dict) else {}
        if target:
            env_deps.append(
                f"{role}: image {target.get('image', '?')} ({target.get('image_id', 'no id')})"
            )
    if isinstance(provenance.get("network"), dict):
        env_deps.append(
            f"network: {provenance['network'].get('name', '?')} internal={provenance['network'].get('internal')}"
        )
    if isinstance(invocation.get("resource_limits"), dict):
        limits = invocation["resource_limits"]
        env_deps.append(
            "resource limits: memory={memory} cpus={cpus} pids={pids_limit}".format(
                memory=limits.get("memory", "?"),
                cpus=limits.get("cpus", "?"),
                pids_limit=limits.get("pids_limit", "?"),
            )
        )
    if provenance.get("module_sha256"):
        env_deps.append(f"module sha256: {provenance['module_sha256']}")
    for key in ("php_ini_sha256", "apache_conf_sha256", "probe_sha256"):
        if provenance.get(key):
            env_deps.append(f"{key}: {provenance[key]}")
    if not env_deps:
        env_deps.append("environment not recorded; reproducibility is limited")

    evidence_refs = []
    if result.get("_source"):
        evidence_refs.append(str(result["_source"]))
    if provenance.get("_source"):
        evidence_refs.append(str(provenance["_source"]))
    for item in artifacts:
        if isinstance(item, dict) and item.get("path"):
            evidence_refs.append(str(item["path"]))
    if isinstance(provenance.get("module_container"), dict):
        if provenance["module_container"].get("logs"):
            evidence_refs.append(str(provenance["module_container"]["logs"]))
    if marker:
        evidence_refs.append(marker)
    if out_path:
        evidence_refs.append(out_path)

    remediation = "Apply the vendor patch for the branch gate; keep interim controls as defense-in-depth."
    if impact == "demonstrated-code-execution":
        remediation = (
            "Patch immediately, isolate the asset, preserve this evidence bundle, and start incident response."
        )
    elif impact in ("memory-disclosure", "memory-safety-failure"):
        remediation = (
            "Patch immediately and treat the worker as compromised until the patch is verified; preserve this evidence."
        )
    elif impact == "crash-oom":
        remediation = (
            "Patch to the branch gate; the OOM/crash is an availability issue, not proof of code execution."
        )
    elif not applicable:
        remediation = "No action for this path; the target meets the patch gate or is not web-reachable."

    output = {
        "kind": "impact-classification",
        "schema": SCHEMA,
        "generated_at": utcnow(),
        "asset": asset,
        "module_id": module_id or "none",
        "synthetic": synthetic,
        "impact": impact,
        "confidence": confidence,
        "applicable": applicable,
        "basis": basis,
        "reasons": reasons,
        "checks": checks,
        "negative_controls": negative_controls,
        "corroboration": {
            "marker_in_target": marker_in_target,
            "control_marker_in_target": control_marker_in_target,
            "marker_sha256": marker_sha,
            "execution_corroborated": execution_corroborated,
            "canary_supplied": bool(canary_bytes),
            "vulnerable_oom_corroborated": v_oom_log or v_oom_resp,
            "patched_oom_corroborated": p_oom_log or p_oom_resp,
        },
        "reproduction_steps": reproduction_steps,
        "environment_dependencies": env_deps,
        "evidence_refs": evidence_refs,
        "limitations": limitations,
        "remediation": remediation,
    }
    return output


# --------------------------------------------------------------------------- #
# manifest validation
# --------------------------------------------------------------------------- #

def validate_manifest(directory: str, allow_synthetic: bool) -> tuple[dict, int]:
    reasons: list[str] = []
    path = os.path.join(directory, "module.json")
    manifest = load_json(path)
    if not isinstance(manifest, dict):
        return {
            "kind": "module-manifest-validation",
            "schema": SCHEMA,
            "valid": False,
            "reasons": [f"cannot read a JSON object at {path}"],
            "manifest": None,
        }, 4

    if manifest.get("kind") != "php2shell-validation-module":
        reasons.append("kind must be 'php2shell-validation-module'")
    if manifest.get("schema") != SCHEMA:
        reasons.append("schema must be 1")
    module_id = manifest.get("id")
    if not isinstance(module_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,63}", module_id):
        reasons.append("id must be 2-64 lowercase [a-z0-9-] characters")
    if not isinstance(manifest.get("version"), str) or not manifest.get("version").strip():
        reasons.append("version must be a non-empty string")

    runtime = manifest.get("runtime") if isinstance(manifest.get("runtime"), dict) else {}
    image = runtime.get("image")
    if image is not None and (not isinstance(image, str) or not image.strip()):
        reasons.append("runtime.image must be a non-empty string when present")
    entrypoint = runtime.get("entrypoint")
    if not isinstance(entrypoint, list) or not entrypoint:
        reasons.append("runtime.entrypoint must be a non-empty array")
    else:
        for part in entrypoint:
            if not isinstance(part, str) or not part or "\x00" in part:
                reasons.append("runtime.entrypoint entries must be non-empty strings")
                continue
            if ".." in part.replace("\\", "/").split("/"):
                reasons.append(f"runtime.entrypoint contains '..': {part!r}")
        first = entrypoint[0]
        if isinstance(first, str):
            base = os.path.basename(first)
            if "/" in first or base not in ALLOWED_INTERPRETERS:
                reasons.append(
                    f"runtime.entrypoint[0] must be one of {sorted(ALLOWED_INTERPRETERS)}, got {first!r}"
                )

    target = manifest.get("target") if isinstance(manifest.get("target"), dict) else {}
    if "ini" in target and not safe_rel_path(target.get("ini")):
        reasons.append("target.ini must be a safe relative path")
    if "apache_conf" in target and not safe_rel_path(target.get("apache_conf")):
        reasons.append("target.apache_conf must be a safe relative path")
    files = target.get("files")
    if files is not None:
        if not isinstance(files, dict):
            reasons.append("target.files must be an object")
        else:
            for key, value in files.items():
                if not safe_rel_path(key):
                    reasons.append(f"target.files key is not safe: {key!r}")
                if not safe_rel_path(value):
                    reasons.append(f"target.files value is not safe: {value!r}")

    requires = manifest.get("requires") if isinstance(manifest.get("requires"), dict) else {}
    if "external_exploit" in requires and not isinstance(requires.get("external_exploit"), bool):
        reasons.append("requires.external_exploit must be a boolean when present")

    output = manifest.get("output", "module-result.json")
    if not safe_rel_path(output):
        reasons.append("output must be a safe relative path")

    claims = manifest.get("claims") if isinstance(manifest.get("claims"), dict) else {}
    if not isinstance(claims.get("synthetic"), bool):
        reasons.append("claims.synthetic must be a boolean")
    synthetic = bool(claims.get("synthetic"))
    max_impact = claims.get("max_impact")
    if max_impact not in TAXONOMY:
        reasons.append(f"claims.max_impact must be one of {list(TAXONOMY)}")
    if synthetic and not allow_synthetic:
        reasons.append("synthetic module requires --allow-synthetic")

    valid = not reasons
    return {
        "kind": "module-manifest-validation",
        "schema": SCHEMA,
        "valid": valid,
        "synthetic": synthetic,
        "reasons": reasons,
        "manifest": manifest,
        "module_dir": os.path.abspath(directory),
        "module_json_sha256": sha256_file(path),
        "output": output,
    }, 0 if valid else 4


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(description="Classify validation-module evidence")
    parser.add_argument("--validate-manifest", metavar="DIR")
    parser.add_argument("--run", help="module-run.json produced by module-run.sh")
    parser.add_argument("--result", help="module-result.json")
    parser.add_argument("--provenance", help="harness provenance JSON")
    parser.add_argument("--result-dir", help="directory containing module artifacts")
    parser.add_argument("--context", help="audit context JSON (no module run)")
    parser.add_argument("--rce", help="rce-validate.sh JSON output")
    parser.add_argument("--marker", help="marker file for execution proof")
    parser.add_argument("--canary", help="disclosure canary (classifier-only)")
    parser.add_argument("--allow-synthetic", action="store_true")
    parser.add_argument("--out")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.validate_manifest:
        report, code = validate_manifest(args.validate_manifest, args.allow_synthetic)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                json.dump(report, fh, indent=2, sort_keys=True)
                fh.write("\n")
        if args.json:
            print(json.dumps(report, ensure_ascii=False))
        elif not report["valid"]:
            print("INVALID MODULE MANIFEST")
            for reason in report["reasons"]:
                print(f"  - {reason}")
        else:
            print(
                "VALID MODULE MANIFEST: "
                f"{report['manifest'].get('id')} {report['manifest'].get('version')}"
            )
        return code

    if args.run:
        run = load_json(args.run)
        if not isinstance(run, dict):
            print(f"cannot read run artifact: {args.run}", file=sys.stderr)
            return 4
        result = run.get("result") if isinstance(run.get("result"), dict) else None
        provenance = run
        if result is None and args.result:
            result = load_json(args.result)
        result_dir = args.result_dir or os.path.dirname(os.path.abspath(args.run))
    else:
        result = load_json(args.result) if args.result else None
        provenance = load_json(args.provenance) if args.provenance else {}
        result_dir = args.result_dir or (os.path.dirname(os.path.abspath(args.result)) if args.result else None)

    if args.context:
        context = load_json(args.context)
        if not isinstance(context, dict):
            print(f"cannot read context: {args.context}", file=sys.stderr)
            return 4
    else:
        context = None

    if result is None and context is None:
        print("one of --run, --result, --context, or --validate-manifest is required", file=sys.stderr)
        return 4

    rce = load_json(args.rce) if args.rce else None
    if not isinstance(rce, dict):
        rce = None

    if isinstance(result, dict) and args.result:
        result["_source"] = args.result
    if isinstance(provenance, dict) and args.run:
        provenance["_source"] = args.run

    report = classify_result(
        result=result if isinstance(result, dict) else None,
        provenance=provenance if isinstance(provenance, dict) else None,
        result_dir=result_dir,
        rce=rce,
        marker=args.marker,
        canary=args.canary,
        context=context,
        out_path=args.out,
    )

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
            fh.write("\n")
    if args.json:
        print(json.dumps(report, ensure_ascii=False))
    else:
        print(f"IMPACT:     {report['impact']}")
        print(f"CONFIDENCE: {report['confidence']}")
        print(f"ASSET:      {report['asset']}")
        print(f"MODULE:     {report['module_id']} (synthetic={report['synthetic']})")
        if report["basis"]:
            print("BASIS:")
            for item in report["basis"]:
                print(f"  - {item}")
        if report["reasons"]:
            print("REASONS:")
            for item in report["reasons"]:
                print(f"  - {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
