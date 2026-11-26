"""
security.py - Strict Loopback Origin/Host Guards, Body Caps, and SSRF Validators.
Zero external dependencies (Python 3.10+ standard library).
Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
"""

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional, Tuple

MAX_BODY_BYTES = 1_048_576  # 1 MiB hard cap

_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_BLOCKED_METADATA_HOSTS = frozenset({
    "metadata.google.internal",
    "metadata.goog",
    "metadata",
    "instance-data",
})
_BLOCKED_METADATA_IPS = frozenset({
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("fd00:ec2::254"),
})


def is_local_origin(origin: Optional[str]) -> bool:
    """Strict browser Origin check against localhost / 127.0.0.1 / [::1].
    No Origin header = non-browser client (CLI/SDK/agent): allowed.
    Rejects port-suffix bypasses like http://127.0.0.1:8098.example.invalid,
    embedded credentials, and non-http(s) schemes."""
    if not origin:
        return True
    raw = str(origin).strip()
    if not raw or raw.lower() == "null":
        return False
    try:
        u = urllib.parse.urlparse(raw)
        if u.scheme not in ("http", "https"):
            return False
        if u.username is not None or u.password is not None:
            return False
        if u.path not in ("", "/") or u.params or u.query or u.fragment:
            return False
        hostname = u.hostname
        if not hostname or hostname.lower() not in _LOCAL_HOSTS:
            return False
        port = u.port  # Raises ValueError on port-suffix attacks like :8098.example.invalid
        if port is not None and not (1 <= port <= 65535):
            return False
        host_literal = f"[{hostname}]" if ":" in hostname else hostname
        expected_netloc = f"{host_literal}:{port}" if port is not None else host_literal
        return u.netloc.lower() == expected_netloc.lower()
    except ValueError:
        return False


def is_local_host(host_header: Optional[str]) -> bool:
    """Strict loopback Host header check to prevent DNS rebinding attacks.
    Accepts localhost, 127.0.0.1, [::1] with optional numeric port."""
    if not host_header:
        return True
    raw = str(host_header).strip()
    if not raw or any(ch.isspace() for ch in raw):
        return False
    try:
        u = urllib.parse.urlparse(f"http://{raw}")
        if u.username is not None or u.password is not None:
            return False
        if u.path or u.params or u.query or u.fragment:
            return False
        hostname = u.hostname
        if not hostname or hostname.lower() not in _LOCAL_HOSTS:
            return False
        port = u.port
        if port is not None and not (1 <= port <= 65535):
            return False
        host_literal = f"[{hostname}]" if ":" in hostname else hostname
        expected_netloc = f"{host_literal}:{port}" if port is not None else host_literal
        return u.netloc.lower() == expected_netloc.lower()
    except ValueError:
        return False


def cors_origin_for(handler) -> Optional[str]:
    """Return the validated Origin header to echo in Access-Control-Allow-Origin, or None."""
    origin = handler.headers.get("Origin")
    if origin and is_local_origin(origin):
        return origin.strip()
    return None


def read_request_body(
    handler,
    max_bytes: int = MAX_BODY_BYTES,
) -> Tuple[Optional[bytes], Optional[Tuple[int, str]]]:
    """Safely validate Content-Length and read request body up to max_bytes.
    Returns (raw_bytes, None) on success, or (None, (status_code, error_msg)) on error."""
    cl_header = handler.headers.get("Content-Length")
    if cl_header is None or cl_header == "":
        return b"", None
    cl_clean = cl_header.strip()
    if not cl_clean.isdigit():
        return None, (400, "Invalid Content-Length header")
    length = int(cl_clean)
    if length < 0:
        return None, (400, "Invalid negative Content-Length header")
    if length > max_bytes:
        return None, (413, f"Payload exceeds maximum body limit of {max_bytes} bytes")
    if length == 0:
        return b"", None
    return handler.rfile.read(length), None


def _is_ip_allowed(ip_obj, allow_loopback: bool) -> Tuple[bool, str]:
    if ip_obj in _BLOCKED_METADATA_IPS:
        return False, f"Blocked cloud metadata IP: {ip_obj}"
    if ip_obj.is_link_local:
        return False, f"Blocked link-local IP: {ip_obj}"
    if ip_obj.is_unspecified or ip_obj.is_multicast or ip_obj.is_reserved:
        return False, f"Blocked non-routable IP: {ip_obj}"
    if ip_obj.is_loopback:
        if allow_loopback:
            return True, "ok"
        return False, f"Blocked loopback upstream IP: {ip_obj}"
    if ip_obj.is_private:
        return False, f"Blocked private network IP: {ip_obj}"
    return True, "ok"


def validate_upstream_url(url: str, allow_loopback: bool = False) -> Tuple[bool, str]:
    """Validate an upstream proxy URL against SSRF (private/loopback/link-local/IMDS IPs).
    Even when allow_loopback=True (for local test mocks), IMDS/link-local/RFC1918 remain blocked."""
    if not url or not isinstance(url, str):
        return False, "Empty upstream URL"
    raw = url.strip()
    try:
        u = urllib.parse.urlparse(raw)
        if u.scheme not in ("http", "https"):
            return False, f"Unsupported upstream scheme: {u.scheme or 'none'}"
        if u.username is not None or u.password is not None:
            return False, "Embedded credentials in upstream URL are forbidden"
        hostname = u.hostname
        if not hostname:
            return False, "Missing upstream hostname"
        port = u.port
        if port is not None and not (1 <= port <= 65535):
            return False, "Invalid upstream port"
    except ValueError as exc:
        return False, f"Malformed upstream URL: {exc}"

    host_lower = hostname.lower().rstrip(".")
    if host_lower in _BLOCKED_METADATA_HOSTS:
        return False, f"Blocked metadata hostname: {hostname}"

    # 1. Literal IP check
    try:
        ip_literal = ipaddress.ip_address(host_lower)
        return _is_ip_allowed(ip_literal, allow_loopback=allow_loopback)
    except ValueError:
        pass

    # 2. Localhost name check
    if host_lower == "localhost" or host_lower.endswith(".localhost"):
        if allow_loopback:
            return True, "ok"
        return False, f"Blocked loopback hostname: {hostname}"

    # 3. DNS resolution check against private/loopback/IMDS ranges
    resolved_port = port or (443 if u.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(hostname, resolved_port, type=socket.SOCK_STREAM)
    except OSError as exc:
        return False, f"Unable to resolve upstream hostname '{hostname}': {exc}"

    if not infos:
        return False, f"No DNS records resolved for '{hostname}'"

    for _family, _socktype, _proto, _canon, sockaddr in infos:
        addr_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(addr_str)
        except ValueError:
            return False, f"Invalid resolved IP '{addr_str}'"
        ok, reason = _is_ip_allowed(ip_obj, allow_loopback=allow_loopback)
        if not ok:
            return False, reason

    return True, "ok"


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Blocks all HTTP 3xx redirects to prevent redirect-based SSRF bypasses."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url,
            403,
            f"Upstream HTTP redirect ({code}) blocked by firewall SSRF policy",
            headers,
            fp,
        )
