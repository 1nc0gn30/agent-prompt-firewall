"""
web_radar.py - Web Radar Dashboard, REST API, and Real-Time SSE Telemetry Feed.
Listens on port 8098. Serves pure CSS/Vanilla JS UI and SSE event streaming.
Zero external dependencies (Python 3.10+ standard library).
Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
"""

import json
import mimetypes
import os
import queue
import threading
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Optional, Dict, Any, Tuple

from .detector import ThreatDetector
from .redactor import Redactor
from .security import (
    MAX_BODY_BYTES,
    cors_origin_for,
    is_local_host,
    is_local_origin,
    read_request_body,
)
from .storage import FirewallStorage, GLOBAL_BROADCASTER

VERSION = "2.6.0"

# Backwards-compatible exports for tests
_is_local_origin = is_local_origin


def _cors_origin(handler) -> Optional[str]:
    return cors_origin_for(handler)


def _safe_rel(raw: str) -> str:
    """Request path -> safe relative path inside a static dir; '' (index) if it
    tries to climb out with '..' or is absolute. Raw request paths are not normalised."""
    rel = urllib.parse.unquote(str(raw or "")).replace("\\", "/").lstrip("/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts) or ":" in (parts[0] if parts else ""):
        return ""
    return "/".join(parts)


def _has_traversal_attempt(raw_path: str) -> bool:
    """Detect path traversal attempts across raw, single-decoded, and double-decoded paths."""
    candidates = [
        str(raw_path or ""),
        urllib.parse.unquote(str(raw_path or "")),
        urllib.parse.unquote(urllib.parse.unquote(str(raw_path or ""))),
    ]
    for cand in candidates:
        if "\\" in cand or "\x00" in cand:
            return True
        norm = cand.lstrip("/")
        parts = norm.split("/")
        if any(p == ".." for p in parts):
            return True
        if parts and ":" in parts[0]:
            return True
    return False


def _parse_limit_query(raw_query: str, default: int = 50, maximum: int = 500) -> Tuple[Optional[int], Optional[str]]:
    if not raw_query:
        return default, None
    params = urllib.parse.parse_qs(raw_query, keep_blank_values=True)
    if "limit" not in params:
        return default, None
    raw_val = params["limit"][0].strip()
    try:
        val = int(raw_val)
    except ValueError:
        return None, "Query parameter 'limit' must be a positive integer"
    if val < 1:
        return None, "Query parameter 'limit' must be >= 1"
    return min(val, maximum), None


class ThreadedWebServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class FirewallRequestHandler(BaseHTTPRequestHandler):
    storage: Optional[FirewallStorage] = None
    detector: ThreatDetector = ThreatDetector(block_threshold=0.70)
    redactor: Redactor = Redactor()
    proxy_port: int = 8198
    public_dir: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "public"))

    _KNOWN_API_GET_PATHS = frozenset({
        "/health",
        "/api/health",
        "/status",
        "/api/status",
        "/api/stats",
        "/api/threats",
        "/api/scans",
        "/api/config",
        "/api/audit/export",
        "/api/events/stream",
        "/api/stream",
    })

    def log_message(self, format, *args):
        pass

    def _set_headers(
        self,
        status: int = 200,
        content_type: str = "application/json",
        include_cors: bool = True,
    ):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Vary", "Origin")
        if include_cors:
            allowed = cors_origin_for(self)
            if allowed:
                self.send_header("Access-Control-Allow-Origin", allowed)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header(
            "Content-Security-Policy",
            "frame-ancestors 'self' http://127.0.0.1:* http://localhost:* https://zoth.nullai.tech",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")

    def _send_json(
        self,
        status: int,
        payload: Any,
        include_cors: bool = True,
        extra_headers: Optional[Dict[str, str]] = None,
        is_head: bool = False,
    ):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self._set_headers(status, "application/json", include_cors=include_cors)
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not is_head:
            self.wfile.write(body)

    def _enforce_host_guard(self, is_head: bool = False) -> bool:
        if not is_local_host(self.headers.get("Host")):
            self._send_json(403, {"error": "forbidden host header"}, include_cors=False, is_head=is_head)
            return False
        return True

    def _enforce_origin_guard(self, is_head: bool = False) -> bool:
        origin = self.headers.get("Origin")
        if origin and not is_local_origin(origin):
            self._send_json(403, {"error": "cross-origin request blocked"}, include_cors=False, is_head=is_head)
            return False
        return True

    def _split_url(self) -> Tuple[str, str]:
        if "?" in self.path:
            p, q = self.path.split("?", 1)
            return p, q
        return self.path, ""

    def do_OPTIONS(self):
        if not self._enforce_host_guard():
            return
        if not self._enforce_origin_guard():
            return
        self._set_headers(204, "text/plain")
        self.end_headers()

    def do_HEAD(self):
        if not self._enforce_host_guard(is_head=True):
            return
        path, _query = self._split_url()
        if path in self._KNOWN_API_GET_PATHS or path.startswith("/api/"):
            if not self._enforce_origin_guard(is_head=True):
                return
            if path not in self._KNOWN_API_GET_PATHS:
                self._send_json(404, {"error": f"Endpoint not found: {path}"}, is_head=True)
                return
            if path in ("/api/events/stream", "/api/stream"):
                self._set_headers(200, "text/event-stream")
                self.end_headers()
                return
            self._set_headers(200, "application/json")
            self.end_headers()
            return

        self._serve_file(path, is_head=True)

    def do_GET(self):
        if not self._enforce_host_guard():
            return
        path, query = self._split_url()
        web_port = self.server.server_port

        # Enforce strict Origin check on all API and telemetry endpoints
        if path in self._KNOWN_API_GET_PATHS or path.startswith("/api/"):
            if not self._enforce_origin_guard():
                return

        if path in ("/health", "/api/health", "/status", "/api/status"):
            stats = self.storage.get_stats() if self.storage else {}
            self._send_json(200, {
                "status": "ok",
                "service": "agent-prompt-firewall",
                "version": VERSION,
                "web_port": web_port,
                "proxy_port": self.proxy_port,
                "block_threshold": self.detector.block_threshold,
                "stats": stats,
                "license": "100% Free & Open Access (Zero Paywalls)",
            })
            return

        if path == "/api/stats":
            stats = self.storage.get_stats() if self.storage else {}
            self._send_json(200, stats)
            return

        if path == "/api/threats":
            limit, err = _parse_limit_query(query, default=50, maximum=500)
            if err:
                self._send_json(400, {"error": err})
                return
            threats = self.storage.get_recent_threats(limit) if self.storage else []
            self._send_json(200, threats)
            return

        if path == "/api/scans":
            limit, err = _parse_limit_query(query, default=50, maximum=500)
            if err:
                self._send_json(400, {"error": err})
                return
            scans = self.storage.get_recent_scans(limit) if self.storage else []
            self._send_json(200, scans)
            return

        if path == "/api/audit/export":
            limit, err = _parse_limit_query(query, default=500, maximum=500)
            if err:
                self._send_json(400, {"error": err})
                return
            audit = (
                self.storage.export_compliance_audit(limit=limit)
                if self.storage
                else {"version": VERSION, "chain_verification": {"valid": True, "total_entries": 0}, "scans": []}
            )
            self._send_json(
                200,
                audit,
                extra_headers={"Content-Disposition": 'attachment; filename="agent-prompt-firewall-audit.json"'},
            )
            return

        if path == "/api/config":
            self._send_json(200, {
                "version": VERSION,
                "web_port": web_port,
                "proxy_port": self.proxy_port,
                "block_threshold": self.detector.block_threshold,
                "pii_rules": ["SSN", "EMAIL", "CREDIT_CARD", "PHONE_NUMBER"],
                "secret_rules": ["OPENAI", "ANTHROPIC", "GOOGLE", "AWS", "GITHUB", "STRIPE", "PRIVATE_KEY", "DATABASE_URL"],
                "deobfuscation": ["NFKC", "ZERO_WIDTH", "HOMOGLYPH", "HTML_ENTITY", "URL_PERCENT", "ROT13", "LEETSPEAK", "BASE64", "ZLIB", "HEX"],
                "mcp_tools": ["prompt_firewall_scan", "prompt_firewall_redact", "prompt_firewall_stats", "prompt_firewall_threats"],
                "sse_endpoints": ["/api/events/stream", "/api/stream"],
            })
            return

        if path in ("/api/events/stream", "/api/stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache, no-transform")
            self.send_header("Connection", "keep-alive")
            self.send_header("Vary", "Origin")
            allowed = cors_origin_for(self)
            if allowed:
                self.send_header("Access-Control-Allow-Origin", allowed)
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()

            init_stats = self.storage.get_stats() if self.storage else {}
            welcome_payload = {
                "status": "listening",
                "endpoint": path,
                "version": VERSION,
                "web_port": web_port,
                "proxy_port": self.proxy_port,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "stats": init_stats,
            }
            welcome_msg = f"event: connected\ndata: {json.dumps(welcome_payload)}\n\n"
            self.wfile.write(welcome_msg.encode("utf-8"))
            self.wfile.flush()

            sub_queue = GLOBAL_BROADCASTER.subscribe()
            try:
                while True:
                    try:
                        msg = sub_queue.get(timeout=10.0)
                        self.wfile.write(msg.encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        ping_msg = f": heartbeat {int(time.time())}\n\n"
                        self.wfile.write(ping_msg.encode("utf-8"))
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                GLOBAL_BROADCASTER.unsubscribe(sub_queue)
            return

        if path.startswith("/api/"):
            self._send_json(404, {"error": f"Endpoint not found: {path}"})
            return

        self._serve_file(path, is_head=False)

    def do_POST(self):
        if not self._enforce_host_guard():
            return
        if not self._enforce_origin_guard():
            return

        path, _query = self._split_url()

        if path == "/api/scan":
            start_time = time.perf_counter()
            raw_body, err = read_request_body(self, MAX_BODY_BYTES)
            if err is not None:
                status_code, message = err
                self._send_json(status_code, {"error": message})
                return

            if not raw_body:
                self._send_json(400, {"error": "Empty JSON body"})
                return

            try:
                data = json.loads(raw_body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "Malformed JSON body"})
                return

            if not isinstance(data, dict):
                self._send_json(400, {"error": "JSON payload must be an object"})
                return

            prompt = data.get("prompt")
            if not isinstance(prompt, str):
                self._send_json(400, {"error": "'prompt' must be a string"})
                return

            direction = data.get("direction", "inbound")
            if not isinstance(direction, str):
                self._send_json(400, {"error": "'direction' must be a string"})
                return

            threshold = None
            if "threshold" in data and data["threshold"] is not None:
                raw_thr = data["threshold"]
                if isinstance(raw_thr, bool) or not isinstance(raw_thr, (int, float)):
                    self._send_json(400, {"error": "'threshold' must be a number between 0.05 and 0.99"})
                    return
                if not (0.05 <= float(raw_thr) <= 0.99):
                    self._send_json(400, {"error": "'threshold' must be between 0.05 and 0.99"})
                    return
                threshold = float(raw_thr)

            source_ip = self.client_address[0] if self.client_address else "127.0.0.1"

            # 1. Threat Detection & Pre-Storage Secret Redaction
            assessment = self.detector.evaluate(prompt, threshold=threshold)
            redaction = self.redactor.redact(prompt)
            safe_snippet = redaction.redacted_text
            safe_details = [self.redactor.redact(d).redacted_text for d in assessment.details]
            assessment.details = safe_details

            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # 2. Log redacted snippet to SQLite hash-chained ledger
            scan_id = 0
            if self.storage:
                scan_id = self.storage.log_scan({
                    "direction": direction,
                    "prompt_snippet": safe_snippet[:180],
                    "threat_score": assessment.score,
                    "threat_type": assessment.threat_type,
                    "categories": assessment.categories,
                    "details": safe_details,
                    "blocked": assessment.should_block,
                    "redacted_count": redaction.redacted_count,
                    "findings": redaction.findings,
                    "duration_ms": duration_ms,
                    "source_ip": source_ip,
                })

            response_data = {
                "scan_id": scan_id,
                "threat": assessment.to_dict(),
                "redaction": redaction.to_dict(),
                "blocked": assessment.should_block,
                "threshold": threshold if threshold is not None else self.detector.block_threshold,
                "sanitized_prompt": redaction.redacted_text,
                "duration_ms": duration_ms,
            }

            event_payload = {
                "id": scan_id,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_score": assessment.score,
                "score": assessment.score,
                "threat_type": assessment.threat_type,
                "redacted_count": redaction.redacted_count,
                "blocked": assessment.should_block,
                "action": "BLOCKED" if assessment.should_block else "PASSED",
                "source": f"radar:{self.server.server_port}",
                "details": safe_details,
                "snippet": safe_snippet[:120],
                "latency_ms": duration_ms,
            }

            GLOBAL_BROADCASTER.broadcast("threat_event", event_payload)
            self._send_json(200, response_data)
            return

        self._send_json(404, {"error": f"Endpoint not found: {path}"})

    def _serve_file(self, req_path: str, is_head: bool = False):
        if _has_traversal_attempt(req_path):
            self._send_json(403, {"error": "forbidden path"}, is_head=is_head)
            return

        if req_path == "/" or not req_path:
            rel_path = "index.html"
        else:
            rel_path = _safe_rel(req_path) or "index.html"

        public_root = Path(self.public_dir).resolve()
        candidate = (public_root / rel_path).resolve()

        if not candidate.is_relative_to(public_root):
            self._send_json(403, {"error": "forbidden path"}, is_head=is_head)
            return

        if not candidate.is_file():
            # SPA fallback only for extensionless navigation routes; missing assets return 404
            if "." in os.path.basename(rel_path):
                self._send_json(404, {"error": f"Asset not found: {req_path}"}, is_head=is_head)
                return
            candidate = public_root / "index.html"

        if candidate.is_file():
            mime_type, _ = mimetypes.guess_type(str(candidate))
            content_type = mime_type or "application/octet-stream"
            if content_type.startswith("text/") or content_type in ("application/javascript", "application/json", "application/xml"):
                if "charset=" not in content_type:
                    content_type += "; charset=utf-8"

            try:
                content = candidate.read_bytes()
                self._set_headers(200, content_type)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                if not is_head:
                    self.wfile.write(content)
            except Exception as e:
                self._send_json(500, {"error": f"Internal Server Error: {e}"}, is_head=is_head)
        else:
            self._send_json(404, {"error": "Not Found"}, is_head=is_head)


class WebRadarServer:
    """Manager for the Web Radar Dashboard server."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8098,
        storage: Optional[FirewallStorage] = None,
        proxy_port: int = 8198,
        block_threshold: float = 0.70,
    ):
        self.host = host
        self.port = port
        self.storage = storage or FirewallStorage()
        self.proxy_port = proxy_port
        self.block_threshold = block_threshold
        self.server: Optional[ThreadedWebServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        handler_cls = type(
            "BoundFirewallRequestHandler",
            (FirewallRequestHandler,),
            {
                "storage": self.storage,
                "proxy_port": self.proxy_port,
                "detector": ThreatDetector(block_threshold=self.block_threshold),
                "redactor": Redactor(),
            },
        )
        self.server = ThreadedWebServer((self.host, self.port), handler_cls)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        print(f"[*] Web Radar UI active on http://{self.host}:{self.port}")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("[*] Web Radar UI stopped.")
