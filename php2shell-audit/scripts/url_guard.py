#!/usr/bin/env python3
"""url_guard.py — pre-flight URL authorization for scripts/assess-url.sh.

Decides whether a URL may be contacted at all, and returns the exact address
curl should pin (mitigating DNS rebinding). It never talks to the target; the
only network action is `getaddrinfo` on the host being authorized.

Authorization model (safe by default):
  - absolute http/https URLs only; no userinfo/credentials; sane host/port;
  - every resolved address must be globally routable unless --lab is given
    (loopback / private / link-local / unique-local / multicast / reserved /
    unspecified / cloud metadata are all non-global);
  - public hosts must appear in --scope-file (one host per line, '*.suffix'
    wildcards, '#' comments); --lab only authorizes non-global lab addresses,
    it never waives the scope check for a public host;
  - redirect targets re-validate with the same rules; an https->http redirect
    is refused (no silent TLS downgrade);
  - one address is chosen as the "pin" for curl --resolve so later DNS answers
    during the request cannot silently change the destination.

Usage:
  url_guard.py --url URL [--scope-file FILE] [--lab]
  url_guard.py --base BASE --location VALUE [--scope-file FILE] [--lab]

Exit codes: 0 authorized, 2 refused. Output is always one JSON object:
  {"ok": true/false, "reasons": [...], "url": ..., "scheme": ...,
   "host": ..., "port": n, "pin": "...", "addresses": [{"ip","class"}],
   "scope": {"mode": "scope-file"|"lab", "scope_file": ...}}
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import re
import socket
import sys
from urllib.parse import urljoin, urlsplit

SCHEMES = ("http", "https")
DEFAULT_PORTS = {"http": 80, "https": 443}
BAD_CHARS = re.compile(r"[\s\x00-\x1F\x7F]")
META_ADDRS_V4 = {"169.254.169.254", "169.254.170.2"}
META_ADDRS_V6 = {"fd00:ec2::254"}


def classify(ip: ipaddress._BaseAddress) -> str:
    text = str(ip)
    if ip.is_loopback:
        return "loopback"
    if int(ip.version) == 4 and text in META_ADDRS_V4:
        return "metadata"
    if int(ip.version) == 6 and ip in ipaddress.ip_network("fd00:ec2::/48"):
        return "metadata"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    if ip.is_unspecified:
        return "unspecified"
    if int(ip.version) == 6 and (
        ip in ipaddress.ip_network("fc00::/7") or text.startswith("fc") or text.startswith("fd")
    ):
        return "unique-local"
    if ip.is_private:
        return "private"
    return "global"


def valid_hostname(host: str) -> bool:
    if len(host) > 253 or ".." in host:
        return False
    parts = host.split(".")
    return all(p and len(p) <= 63 and re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts)


def load_scope(path: str) -> list[str]:
    entries: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.split("#", 1)[0].strip()
                if line:
                    entries.append(line)
    except OSError as exc:
        raise ValueError(f"cannot read scope file {path}: {exc}") from exc
    return entries


def in_scope(host: str, entries: list[str]) -> str | None:
    """Return the scope entry that authorizes host, or None."""
    for entry in entries:
        if host == entry:
            return entry
        if entry.startswith("*.") and host.endswith(entry[1:]):
            return entry
    return None


def resolve(host: str, port: int) -> list[tuple[str, str]]:
    try:
        infos = socket.getaddrinfo(host, port, family=0, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"dns-unresolved: {host}: {exc}") from exc
    seen: dict[str, str] = {}
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split("%", 1)[0])
        except ValueError:
            continue
        cls = classify(ip)
        if addr not in seen:
            seen[addr] = cls
    return [(addr, cls) for addr, cls in seen.items()]


def guard(url: str, base: str, location: str, scope_path: str, lab: bool) -> dict:
    reasons: list[str] = []
    joined = url

    if base and location is not None:
        if not base.strip():
            reasons.append("malformed: empty base URL for redirect resolution")
            return _out(False, "", reasons)
        joined = urljoin(base.strip(), str(location).strip())
        try:
            base_scheme = urlsplit(base.strip()).scheme.lower()
            base_host = (urlsplit(base.strip()).hostname or "").lower()
        except ValueError:
            base_scheme, base_host = "", ""
    else:
        base_scheme = ""

    if not joined or not str(joined).strip():
        return _out(False, "", ["malformed: empty URL"])
    value = str(joined).strip()
    if BAD_CHARS.search(value):
        return _out(False, value, ["malformed: URL contains whitespace or control characters"])
    if any(ch in value for ch in ("\\", "<", ">", '"')):
        return _out(False, value, ["malformed: URL contains a backslash, quote, or angle bracket"])

    try:
        parts = urlsplit(value)
    except ValueError as exc:
        return _out(False, value, [f"malformed: cannot parse URL: {exc}"])

    scheme = (parts.scheme or "").lower()
    if not parts.netloc:
        return _out(False, value, ["malformed: URL has no authority (host) part"])
    if scheme not in SCHEMES:
        return _out(
            False,
            value,
            [f"unsupported-scheme: {scheme or '(none)'}; only http and https are allowed"],
        )
    if base_scheme == "https" and scheme == "http":
        return _out(
            False,
            value,
            [f"scheme-downgrade: https redirect target is plain http ({value})"],
        )

    if parts.username or parts.password or "@" in (parts.netloc or ""):
        return _out(False, value, ["credentials: URL embeds userinfo (user:pass@host); refused"])

    host = (parts.hostname or "").lower()
    if not host:
        return _out(False, value, ["malformed: URL has no host"])
    if len(host) > 253 or BAD_CHARS.search(host):
        return _out(False, value, ["malformed: invalid host"])
    if "%" in host:
        return _out(
            False,
            value,
            ["malformed: scoped IPv6 zone identifier refused (interface-specific, unreliable for DNS pinning)"],
        )

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is None and not valid_hostname(host):
        return _out(False, value, [f"malformed: invalid hostname '{host}'"])

    try:
        explicit_port = parts.port
    except ValueError:
        return _out(False, value, [f"malformed: invalid port in URL '{value}'"])
    if explicit_port is None:
        port = DEFAULT_PORTS[scheme]
    else:
        port = explicit_port
    if not (1 <= port <= 65535):
        return _out(False, value, [f"malformed: port {port} out of range"])

    entries: list[str] = []
    if scope_path:
        try:
            entries = load_scope(scope_path)
        except ValueError as exc:
            return _out(False, value, [str(exc)])

    # Scope check first: an unlisted host is refused without any DNS lookup,
    # and a listed host is never contacted before its name resolves later.
    scope_entry = ""
    if entries:
        scope_entry = in_scope(host, entries) or ""
        if not scope_entry:
            reasons.append(
                f"not-in-scope: target '{host}' is not listed in the authorized scope file"
            )
            return _out(False, value, reasons, scheme=scheme)

    addresses: list[tuple[str, str]] = []
    if ip is not None:
        addresses = [(str(ip), classify(ip))]
    else:
        try:
            addresses = resolve(host, port)
        except ValueError as exc:
            return _out(False, value, [str(exc)], port=port, scheme=scheme)
        if not addresses:
            return _out(
                False,
                value,
                [f"dns-unresolved: {host} resolved to no usable address"],
                port=port,
                scheme=scheme,
            )

    nonglobal = [(addr, cls) for addr, cls in addresses if cls != "global"]
    allowed = [(addr, cls) for addr, cls in addresses if cls == "global"]

    if nonglobal and not lab:
        worst = sorted({cls for _, cls in nonglobal})
        return _out(
            False,
            value,
            [
                "non-global-address: host {h} resolves to {c}; only --lab may contact "
                "loopback/private/link-local/metadata addresses".format(
                    h=host, c=", ".join(worst)
                )
            ],
            addresses=addresses,
            port=port,
            scheme=scheme,
        )

    if not entries and allowed:
        reasons.append(
            f"not-in-scope: public target '{host}' must appear in --scope-file "
            "(--lab only authorizes non-global lab addresses)"
        )
        return _out(False, value, reasons, addresses=addresses, port=port, scheme=scheme)

    pin = allowed[0][0] if allowed else nonglobal[0][0]
    scope_mode = "scope-file" if allowed else ("lab" if lab else "none")

    return _out(
        True,
        value,
        reasons,
        scheme=scheme,
        host=host,
        port=port,
        pin=pin,
        addresses=addresses,
        scope_mode=scope_mode,
        scope_entry=scope_entry or ("lab-mode" if nonglobal else ""),
    )


def _out(
    ok: bool,
    url: str,
    reasons: list[str],
    scheme: str = "",
    host: str = "",
    port: int = 0,
    pin: str = "",
    addresses: list[tuple[str, str]] | None = None,
    scope_mode: str = "",
    scope_entry: str = "",
) -> dict:
    return {
        "ok": ok,
        "reasons": reasons,
        "url": url,
        "scheme": scheme,
        "host": host,
        "port": port,
        "pin": pin,
        "addresses": [{"ip": addr, "class": cls} for addr, cls in (addresses or [])],
        "scope": {"mode": scope_mode, "entry": scope_entry},
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="URL preflight guard for assess-url.sh")
    parser.add_argument("--url", help="absolute target URL to authorize")
    parser.add_argument("--base", help="base URL for resolving a redirect Location")
    parser.add_argument("--location", help="Location header value to resolve against --base")
    parser.add_argument("--scope-file", dest="scope_file", help="authorized host list")
    parser.add_argument("--lab", action="store_true", help="permit non-global lab addresses")
    args = parser.parse_args()

    if bool(args.url) == bool(args.base or args.location is not None):
        parser.error("give exactly one of --url, or --base with --location")

    if args.base and args.location is None:
        parser.error("--base requires --location")

    try:
        result = guard(
            args.url or "",
            args.base or "",
            args.location,
            args.scope_file or "",
            bool(args.lab),
        )
    except Exception as exc:  # defensive: never crash with a traceback
        result = _out(False, args.url or "", [f"internal: {exc}"])

    print(json.dumps(result, ensure_ascii=False))
    return 0 if result.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
