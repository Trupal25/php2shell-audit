#!/usr/bin/env python3
"""Opt-in RCE validation module for the php:8.4.26-apache / mod_php lab.

The module does not contain an exploit. It expects an externally supplied,
authorized copy of the public php2shell upstream trigger to be mounted at
``$P2S_EXPLOIT_DIR`` (``/opt/php2shell-upstream`` by default). The harness
mounts that directory read-only with ``--exploit-dir``.

The module only targets the disposable vulnerable/patched lab pair created by
``scripts/module-run.sh``. It never accepts an arbitrary URL and never runs on
the host network.

What it does:

1. preflight the vulnerable and patched endpoints and record their PHP
   version/SAPI/INI;
2. instrument a temporary copy of the upstream trigger so the final stage-3
   POST body and response are written to the evidence directory;
3. run the trigger against the vulnerable target with the short command
   ``echo $N>/tmp/m`` (the target receives ``N=<harness nonce>``);
4. run the same trigger once against the patched control;
5. write an ``rce-validation`` artifact and a ``module-result.json``.

The module never claims success on its own. It cannot read the target
filesystem; the harness independently retrieves ``/tmp/m`` from both target
containers, checks the hashes, and only then can the classifier promote the
result to ``demonstrated-code-execution``.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

SCHEMA = 1
MODULE_ID = "rce-modphp"
MODULE_VERSION = "1.0.0"

# The command is embedded in the upstream 167-byte zend_string carrier. Its
# maximum length is 14 bytes. The target container receives N=<nonce>.
COMMAND = "echo $N>/tmp/m"
MARKER_PATH = "/tmp/m"

# yaml-style offset constants for php:8.4.26-apache (Debian 12, amd64). They
# are relative to the libphp.so and Zend MM chunk bases, so they are stable
# across ASLR. A different image/version is refused by the preflight.
ZIF_OFFSET = 0x465370
DTOR_OFFSET = 0x65EB60
HTDATA_OFFSET = 0x690D8
HUGE_MB = 12
EXPECTED_VERSION = "8.4.26"
EXPECTED_MACHINE = {"x86_64", "amd64"}

BODY_ANCHOR = (
    '             extra_headers: dict[str, str] | None = None) -> bytes:\n'
    '        extra = ""\n'
)
BODY_INJECTION = (
    '             extra_headers: dict[str, str] | None = None) -> bytes:\n'
    '        import os as _p2s_os\n'
    '        _p2s_dump = _p2s_os.environ.get("P2S_TRIGGER_DUMP_BODY")\n'
    '        _p2s_is_trigger = False\n'
    '        if _p2s_dump and b"@@CMD@@" in body:\n'
    '            _p2s_is_trigger = True\n'
    '            try:\n'
    '                with open(_p2s_dump, "wb") as _p2s_fh:\n'
    '                    _p2s_fh.write(body)\n'
    '            except OSError:\n'
    '                pass\n'
    '        extra = ""\n'
)
RESPONSE_ANCHOR = (
    '            reader.join(timeout=(timeout or self.timeout) + 1.0)\n'
    '            return bytes(data)\n'
)
RESPONSE_INJECTION = (
    '            reader.join(timeout=(timeout or self.timeout) + 1.0)\n'
    '            _p2s_resp = bytes(data)\n'
    '            if _p2s_is_trigger:\n'
    '                _p2s_dump = _p2s_os.environ.get("P2S_TRIGGER_DUMP_RESPONSE")\n'
    '                if _p2s_dump:\n'
    '                    try:\n'
    '                        with open(_p2s_dump, "wb") as _p2s_fh:\n'
    '                            _p2s_fh.write(_p2s_resp)\n'
    '                    except OSError:\n'
    '                        pass\n'
    '            return _p2s_resp\n'
)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def endpoint(url: str) -> str:
    base = url.rstrip("/")
    if base.endswith("/index.php"):
        base = base[: -len("/index.php")]
    return base + "/index.php"


def probe_endpoint(url: str) -> str:
    base = url.rstrip("/")
    if base.endswith("/index.php"):
        base = base[: -len("/index.php")]
    return base + "/probe.php"


def write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def fetch(url: str, timeout: float = 10.0) -> tuple[int, bytes, str]:
    opener = build_opener(ProxyHandler({}))
    req = Request(
        url,
        headers={
            "User-Agent": "php2shell-rce-module/1.0",
            "Connection": "close",
        },
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            return int(resp.status), resp.read(1 << 20), ""
    except HTTPError as exc:
        try:
            body = exc.read(1 << 20)
        except Exception:
            body = b""
        return int(exc.code), body, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001 - record, never crash the module
        return 0, b"", f"{type(exc).__name__}: {exc}"


def parse_limit_mb(value: str) -> float | None:
    match = re.fullmatch(r"\s*(\d+)\s*([KMG]?)\s*", value or "", re.IGNORECASE)
    if not match:
        return None
    number = int(match.group(1))
    unit = match.group(2).upper()
    if unit == "G":
        return number * 1024.0
    if unit == "M":
        return float(number)
    if unit == "K":
        return number / 1024.0
    return number / (1024.0 * 1024.0)


def probe(url: str) -> dict:
    """GET the lab index and return a small, reproducible observation."""
    status, body, error = fetch(url)
    data: dict = {}
    try:
        parsed = json.loads(body.decode("utf-8", "replace"))
        if isinstance(parsed, dict):
            data = parsed
    except (UnicodeDecodeError, json.JSONDecodeError):
        parsed = None
    ini = data.get("ini") if isinstance(data.get("ini"), dict) else {}
    sapi_raw = str(data.get("sapi") or "")
    sapi = "mod_php" if "apache" in sapi_raw.lower() else sapi_raw
    upload = str(ini.get("session.upload_progress.enabled") or "").strip().lower()
    return {
        "status": status,
        "error": error,
        "body": body,
        "version": str(data.get("version") or ""),
        "sapi_raw": sapi_raw,
        "sapi": sapi,
        "memory_limit": str(ini.get("memory_limit") or ""),
        "memory_limit_mb": parse_limit_mb(str(ini.get("memory_limit") or "")),
        "post_max_size": str(ini.get("post_max_size") or ""),
        "post_max_mb": parse_limit_mb(str(ini.get("post_max_size") or "")),
        "upload_progress_enabled": upload in ("1", "on", "true", "yes"),
    }


def instrument_upstream(source: str) -> tuple[str | None, str]:
    if "P2S_TRIGGER_DUMP_BODY" in source:
        return source, ""
    if BODY_ANCHOR not in source:
        return None, "external exploit source does not contain the expected Target.post anchor"
    if RESPONSE_ANCHOR not in source:
        return None, "external exploit source does not contain the expected Target.post response anchor"
    patched = source.replace(BODY_ANCHOR, BODY_INJECTION.replace("@@CMD@@", COMMAND), 1)
    patched = patched.replace(RESPONSE_ANCHOR, RESPONSE_INJECTION, 1)
    return patched, ""


def run_trigger(
    exploit_path: Path,
    url: str,
    request_path: Path,
    response_path: Path,
    retries: int,
    timeout_s: float,
) -> dict:
    env = dict(os.environ)
    env["P2S_TRIGGER_DUMP_BODY"] = str(request_path)
    env["P2S_TRIGGER_DUMP_RESPONSE"] = str(response_path)
    cmd = [
        sys.executable,
        str(exploit_path),
        "-u",
        url,
        "-c",
        COMMAND,
        "--proof-file",
        "",
        "--profile",
        "bookworm",
        "--zif-offset",
        hex(ZIF_OFFSET),
        "--dtor-offset",
        hex(DTOR_OFFSET),
        "--htdata-offset",
        hex(HTDATA_OFFSET),
        "--huge-mb",
        str(HUGE_MB),
        "--retries",
        str(retries),
        "--timeout",
        "30",
        "--no-auto-offsets",
        "--offsets-file",
        "",
    ]
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
        )
        return {
            "exit": proc.returncode,
            "timed_out": False,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
            "seconds": round(time.time() - started, 3),
        }
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {
            "exit": -1,
            "timed_out": True,
            "stdout": stdout,
            "stderr": stderr,
            "seconds": round(time.time() - started, 3),
        }
    except Exception as exc:  # noqa: BLE001 - record a failed experiment
        return {
            "exit": -1,
            "timed_out": False,
            "stdout": "",
            "stderr": f"{type(exc).__name__}: {exc}",
            "seconds": round(time.time() - started, 3),
        }


def main() -> int:
    started_at = utcnow()
    out = Path(os.environ["P2S_OUTPUT_DIR"])
    module_dir = Path(os.environ["P2S_MODULE_DIR"])
    asset = os.environ.get("P2S_ASSET", "lab-php2shell-module")
    nonce = os.environ.get("P2S_NONCE", "")
    target_url = endpoint(os.environ.get("P2S_TARGET_URL", "http://vulnerable/"))
    control_url = endpoint(os.environ.get("P2S_CONTROL_URL", "http://patched/"))
    target_probe_url = probe_endpoint(os.environ.get("P2S_TARGET_URL", "http://vulnerable/"))
    control_probe_url = probe_endpoint(os.environ.get("P2S_CONTROL_URL", "http://patched/"))
    target_hint = os.environ.get("P2S_TARGET_VERSION", "")
    control_hint = os.environ.get("P2S_CONTROL_VERSION", "")
    exploit_dir = Path(os.environ.get("P2S_EXPLOIT_DIR", "/opt/php2shell-upstream"))
    try:
        budget = max(30, int(os.environ.get("P2S_TIMEOUT_SECONDS", "80")))
    except ValueError:
        budget = 80

    raw = out / "raw"
    raw.mkdir(parents=True, exist_ok=True)

    artifacts: list[dict] = []
    requests: list[dict] = []
    limitations: list[str] = []
    reasons: list[str] = []
    observed_effects: dict = {}

    def add_artifact(rel: str, kind: str, role: str | None = None) -> dict | None:
        path = out / rel
        if not path.is_file():
            return None
        data = path.read_bytes()
        entry = {
            "path": rel,
            "sha256": sha256_bytes(data),
            "bytes": len(data),
            "kind": kind,
        }
        if role:
            entry["role"] = role
        artifacts.append(entry)
        return entry

    def add_request(
        role: str,
        method: str,
        url: str,
        body_path: Path | None,
        response_path: Path | None,
        status: int,
    ) -> None:
        body = body_path.read_bytes() if body_path and body_path.is_file() else b""
        response = response_path.read_bytes() if response_path and response_path.is_file() else b""
        requests.append(
            {
                "role": role,
                "method": method,
                "url": url,
                "body_sha256": sha256_bytes(body),
                "body_bytes": len(body),
                "response_status": status,
                "response_sha256": sha256_bytes(response),
                "response_bytes": len(response),
                "response_excerpt": response[:200].decode("utf-8", "replace"),
            }
        )

    def blocked(status: str, reason: str, extra: dict | None = None) -> int:
        reasons.append(reason)
        result = {
            "kind": "validation-module-result",
            "schema": SCHEMA,
            "module": {"id": MODULE_ID, "version": MODULE_VERSION, "synthetic": False},
            "status": status,
            "asset": asset,
            "nonce": nonce,
            "started_at": started_at,
            "finished_at": utcnow(),
            "targets": {
                "vulnerable": {"url": target_url, "php_version": target_hint},
                "patched": {"url": control_url, "php_version": control_hint},
            },
            "claims": {
                "impact": "inconclusive",
                "execution_effects": [],
            },
            "requests": requests,
            "artifacts": artifacts,
            "observed_effects": observed_effects,
            "evidence": {},
            "limitations": limitations + [reason],
        }
        if extra:
            result.update(extra)
        write_file(out / "module-result.json", (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
        return 0

    if not re.fullmatch(r"[0-9a-fA-F]{16,128}", nonce or ""):
        return blocked("blocked", "harness nonce is missing or outside the 16-128 hex contract")
    marker_expected = (nonce + "\n").encode()
    marker_sha = sha256_bytes(marker_expected)

    # ---- preflight -------------------------------------------------------
    vuln = probe(target_probe_url)
    write_file(raw / "preflight-vulnerable.json", vuln["body"])
    add_artifact("raw/preflight-vulnerable.json", "response", "vulnerable")
    add_request("vulnerable", "GET", target_probe_url, None, raw / "preflight-vulnerable.json", vuln["status"])

    control = probe(control_probe_url)
    write_file(raw / "preflight-patched.json", control["body"])
    add_artifact("raw/preflight-patched.json", "response", "patched")
    add_request("patched", "GET", control_probe_url, None, raw / "preflight-patched.json", control["status"])

    observed_effects.update(
        {
            "vulnerable_preflight_status": vuln["status"],
            "patched_preflight_status": control["status"],
            "vulnerable_php_version": vuln["version"],
            "patched_php_version": control["version"],
            "vulnerable_sapi": vuln["sapi"],
            "patched_sapi": control["sapi"],
        }
    )

    if vuln["status"] != 200 or not vuln["version"]:
        return blocked("blocked", "the vulnerable target did not expose the lab index/version")
    if vuln["version"] != EXPECTED_VERSION:
        return blocked(
            "blocked",
            f"target PHP version {vuln['version']!r} is not the calibrated {EXPECTED_VERSION} build",
        )
    if vuln["sapi"] != "mod_php":
        return blocked("blocked", f"target SAPI {vuln['sapi_raw']!r} is not mod_php")
    if not vuln["upload_progress_enabled"]:
        return blocked("blocked", "session.upload_progress is not enabled on the vulnerable target")
    if vuln["memory_limit_mb"] != 8:
        return blocked(
            "blocked",
            f"target memory_limit {vuln['memory_limit']!r} is not the calibrated 8M profile",
        )
    if (vuln["post_max_mb"] or 0) < 16:
        return blocked("blocked", f"target post_max_size {vuln['post_max_size']!r} is too small for the trigger")
    if platform.machine().lower() not in EXPECTED_MACHINE:
        return blocked("blocked", f"module architecture {platform.machine()!r} is not the calibrated amd64 profile")

    source_path = exploit_dir / "exploit.py"
    if not source_path.is_file():
        return blocked(
            "blocked",
            "external upstream exploit is not mounted; pass --exploit-dir to module-run.sh",
        )
    try:
        source = source_path.read_text(encoding="utf-8")
    except OSError as exc:
        return blocked("blocked", f"cannot read external upstream exploit: {exc}")
    instrumented, why = instrument_upstream(source)
    if instrumented is None:
        return blocked("blocked", why)

    workdir = Path(tempfile.mkdtemp(prefix="p2s-rce-", dir="/tmp"))
    exploit_copy = workdir / "exploit.py"
    write_file(exploit_copy, instrumented.encode())

    # Budget the two runs. The successful run is usually a few seconds; the
    # patched control is deliberately bounded so a failed run cannot consume
    # the whole module budget.
    vuln_timeout = max(20.0, min(60.0, budget - 25.0))
    control_budget = max(15.0, budget - vuln_timeout - 5.0)
    control_timeout = min(35.0, control_budget)

    vuln_request = raw / "trigger-vulnerable.request"
    vuln_response = raw / "trigger-vulnerable.response"
    vuln_run = run_trigger(exploit_copy, target_url, vuln_request, vuln_response, 3, vuln_timeout)
    write_file(raw / "exploit-vulnerable.log", (vuln_run["stdout"] + vuln_run["stderr"]).encode())
    add_artifact("raw/exploit-vulnerable.log", "module-log", "vulnerable")
    observed_effects["vulnerable_exploit_exit"] = vuln_run["exit"]
    observed_effects["vulnerable_exploit_timed_out"] = vuln_run["timed_out"]
    observed_effects["vulnerable_exploit_seconds"] = vuln_run["seconds"]

    vuln_reached_stage3 = "[*] stage 3:" in vuln_run["stdout"]
    vuln_body = vuln_request.read_bytes() if vuln_request.is_file() else b""
    vuln_has_command = COMMAND.encode() in vuln_body
    if vuln_reached_stage3:
        add_artifact("raw/trigger-vulnerable.request", "request-body", "vulnerable")
        if vuln_response.is_file():
            add_artifact("raw/trigger-vulnerable.response", "trigger-response", "vulnerable")
        status_match = re.match(rb"HTTP/\d\.\d\s+(\d{3})", vuln_response.read_bytes() if vuln_response.is_file() else b"")
        add_request(
            "vulnerable",
            "POST",
            target_url,
            vuln_request,
            vuln_response,
            int(status_match.group(1)) if status_match else 0,
        )

    # ---- patched control -------------------------------------------------
    control_request = raw / "trigger-patched.request"
    control_response = raw / "trigger-patched.response"
    control_run = run_trigger(exploit_copy, control_url, control_request, control_response, 1, control_timeout)
    write_file(raw / "exploit-patched.log", (control_run["stdout"] + control_run["stderr"]).encode())
    add_artifact("raw/exploit-patched.log", "module-log", "patched")
    observed_effects["patched_exploit_exit"] = control_run["exit"]
    observed_effects["patched_exploit_timed_out"] = control_run["timed_out"]
    observed_effects["patched_exploit_seconds"] = control_run["seconds"]
    control_reached_stage3 = "[*] stage 3:" in control_run["stdout"]
    if control_reached_stage3:
        add_artifact("raw/trigger-patched.request", "control-request-body", "patched")
        if control_response.is_file():
            add_artifact("raw/trigger-patched.response", "control-trigger-response", "patched")
        status_match = re.match(rb"HTTP/\d\.\d\s+(\d{3})", control_response.read_bytes() if control_response.is_file() else b"")
        add_request(
            "patched",
            "POST",
            control_url,
            control_request,
            control_response,
            int(status_match.group(1)) if status_match else 0,
        )

    if not vuln_reached_stage3:
        return blocked("failed", "the external trigger did not reach stage 3 on the vulnerable target")
    if not vuln_has_command:
        return blocked("failed", "the final vulnerable trigger body does not contain the marker command")

    # ---- evidence --------------------------------------------------------
    evidence = {
        "kind": "rce-validation",
        "schema": SCHEMA,
        "asset": asset,
        "surface": "session.upload_progress",
        "preconditions": {
            "php_version": vuln["version"],
            "web_sapi": "mod_php",
            "upload_progress_enabled": True,
        },
        "validation": {
            "nonce": nonce,
            "triggered_at": utcnow(),
            "request_sha256": sha256_bytes(vuln_body),
            "execution_effects": ["command_execution", "file_write"],
            "marker_sha256": marker_sha,
        },
    }
    write_file(out / "rce-evidence.json", (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode())
    add_artifact("rce-evidence.json", "rce-validation", "vulnerable")

    limitations.extend(
        [
            "The external upstream trigger is not bundled; it was supplied by the operator and mounted read-only.",
            "The module cannot read the target filesystem. The harness independently retrieves /tmp/m from both containers and checks the marker hash.",
            "The recorded request digest is the final stage-3 POST body, not a stored copy of every request.",
            f"The calibrated trigger profile is {EXPECTED_VERSION}/mod_php amd64 with memory_limit=8M and session.upload_progress=On.",
            "The patched control was exercised with a smaller retry budget; any control marker is recorded separately by the harness.",
        ]
    )

    result = {
        "kind": "validation-module-result",
        "schema": SCHEMA,
        "module": {"id": MODULE_ID, "version": MODULE_VERSION, "synthetic": False},
        "status": "completed",
        "asset": asset,
        "nonce": nonce,
        "started_at": started_at,
        "finished_at": utcnow(),
        "targets": {
            "vulnerable": {
                "url": target_url,
                "php_version": vuln["version"],
                "sapi": vuln["sapi"],
            },
            "patched": {
                "url": control_url,
                "php_version": control["version"],
                "sapi": control["sapi"],
            },
        },
        "claims": {
            "impact": "demonstrated-code-execution",
            "execution_effects": ["command_execution", "file_write"],
            "control_stage3_reached": control_reached_stage3,
        },
        "requests": requests,
        "artifacts": artifacts,
        "observed_effects": observed_effects,
        "evidence": {
            "marker_path_in_target": MARKER_PATH,
            "marker_sha256": marker_sha,
            "control_marker_path_in_target": MARKER_PATH,
            "control_marker_sha256": marker_sha,
            "rce_evidence_path": "rce-evidence.json",
        },
        "limitations": limitations,
        "reasons": reasons,
    }
    write_file(out / "module-result.json", (json.dumps(result, indent=2, sort_keys=True) + "\n").encode())
    print(
        "[rce-modphp] stage3 reached; marker is verified by the harness, "
        f"vulnerable_exit={vuln_run['exit']} control_exit={control_run['exit']}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
