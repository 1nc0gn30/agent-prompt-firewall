"""
server.py - Web Radar Dashboard, REST API, and SSE Telemetry Feed.
Listens on port 8098. Serves pure CSS/Vanilla JS UI and API endpoints.
Zero external dependencies (Python 3.10+ standard library).
"""

import json
import mimetypes
import os
import queue
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Optional, Dict, Any, List

from .detector import ThreatDetector
from .redactor import Redactor
from .storage import FirewallStorage, GLOBAL_BROADCASTER


class ThreadedWebServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class FirewallRequestHandler(BaseHTTPRequestHandler):
    storage: FirewallStorage = None
    detector: ThreatDetector = ThreatDetector(block_threshold=0.70)
    redactor: Redactor = Redactor()
    public_dir: str = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "public"))

    def log_message(self, format, *args):
        pass

    def _set_headers(self, status: int = 200, content_type: str = "application/json"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")

    def do_OPTIONS(self):
        self._set_headers(200, "text/plain")
        self.end_headers()

    def do_HEAD(self):
        # Support HEAD requests for automated checkers and crawlers
        path = self.path.split("?")[0]
        if path.startswith("/api/"):
            self._set_headers(200, "application/json")
            self.end_headers()
            return

        self._serve_file(path, is_head=True)

    def do_GET(self):
        path = self.path.split("?")[0]

        if path == "/api/stats":
            stats = self.storage.get_stats() if self.storage else {}
            body = json.dumps(stats, indent=2).encode("utf-8")
            self._set_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        elif path == "/api/threats":
            threats = self.storage.get_recent_threats(50) if self.storage else []
            body = json.dumps(threats, indent=2).encode("utf-8")
            self._set_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        elif path == "/api/scans":
            scans = self.storage.get_recent_scans(50) if self.storage else []
            body = json.dumps(scans, indent=2).encode("utf-8")
            self._set_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        elif path == "/api/config":
            cfg = {
                "version": "0.1.0",
                "web_port": 8098,
                "proxy_port": 8099,
                "block_threshold": 0.70,
                "pii_rules": ["SSN", "EMAIL", "CREDIT_CARD", "PHONE_NUMBER"],
                "secret_rules": ["OPENAI", "ANTHROPIC", "GOOGLE", "AWS", "GITHUB", "STRIPE", "PRIVATE_KEY", "DATABASE_URL"],
                "pro_status": "unlocked_client_side"
            }
            body = json.dumps(cfg, indent=2).encode("utf-8")
            self._set_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        elif path == "/api/stream":
            # SSE Live Stream
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            # Initial connection event
            init_stats = self.storage.get_stats() if self.storage else {}
            welcome_msg = f"event: connected\ndata: {json.dumps({'status': 'listening', 'stats': init_stats})}\n\n"
            self.wfile.write(welcome_msg.encode("utf-8"))
            self.wfile.flush()

            sub_queue = GLOBAL_BROADCASTER.subscribe()
            try:
                while True:
                    try:
                        msg = sub_queue.get(timeout=15.0)
                        self.wfile.write(msg.encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        # Heartbeat keep-alive ping
                        ping_msg = f": heartbeat {int(time.time())}\n\n"
                        self.wfile.write(ping_msg.encode("utf-8"))
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                GLOBAL_BROADCASTER.unsubscribe(sub_queue)
            return

        # Serve static UI files
        self._serve_file(path, is_head=False)

    def do_POST(self):
        path = self.path.split("?")[0]

        if path == "/api/scan":
            start_time = time.perf_counter()
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b""
            
            try:
                data = json.loads(raw_body.decode("utf-8"))
            except Exception:
                data = {"prompt": raw_body.decode("utf-8", errors="ignore")}

            prompt = data.get("prompt", "")
            direction = data.get("direction", "inbound")
            source_ip = self.client_address[0] if self.client_address else "127.0.0.1"

            # 1. Threat Detection
            assessment = self.detector.evaluate(prompt)

            # 2. Redaction
            redaction = self.redactor.redact(prompt)

            duration_ms = round((time.perf_counter() - start_time) * 1000, 2)

            # 3. Log to DB
            scan_id = 0
            if self.storage:
                scan_id = self.storage.log_scan({
                    "direction": direction,
                    "prompt_snippet": prompt[:180],
                    "threat_score": assessment.score,
                    "threat_type": assessment.threat_type,
                    "categories": assessment.categories,
                    "details": assessment.details,
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
                "sanitized_prompt": redaction.redacted_text,
                "duration_ms": duration_ms,
            }

            GLOBAL_BROADCASTER.broadcast("scan_completed", {
                "id": scan_id,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_type": assessment.threat_type,
                "score": assessment.score,
                "blocked": assessment.should_block,
                "redacted_count": redaction.redacted_count,
                "latency_ms": duration_ms,
            })

            body = json.dumps(response_data, indent=2).encode("utf-8")
            self._set_headers(200, "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self._set_headers(404, "application/json")
        body = json.dumps({"error": f"Endpoint not found: {path}"}).encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_file(self, req_path: str, is_head: bool = False):
        if req_path == "/" or not req_path:
            rel_path = "index.html"
        else:
            rel_path = req_path.lstrip("/")

        file_path = os.path.join(self.public_dir, rel_path)
        # Normalize and prevent directory traversal
        if not os.path.abspath(file_path).startswith(os.path.abspath(self.public_dir)):
            self._set_headers(403, "text/plain")
            self.end_headers()
            return

        if not os.path.isfile(file_path):
            # SPA Fallback to index.html
            file_path = os.path.join(self.public_dir, "index.html")

        if os.path.isfile(file_path):
            mime_type, _ = mimetypes.guess_type(file_path)
            content_type = mime_type or "text/plain; charset=utf-8"
            if content_type.startswith("text/"):
                content_type += "; charset=utf-8"

            try:
                with open(file_path, "rb") as f:
                    content = f.read()
                self._set_headers(200, content_type)
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                if not is_head:
                    self.wfile.write(content)
            except Exception as e:
                self._set_headers(500, "text/plain")
                self.end_headers()
                if not is_head:
                    self.wfile.write(f"500 Internal Server Error: {str(e)}".encode("utf-8"))
        else:
            self._set_headers(404, "text/plain")
            self.end_headers()
            if not is_head:
                self.wfile.write(b"404 Not Found")


class WebRadarServer:
    """Manager for the Web Radar Dashboard server."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8098, storage: Optional[FirewallStorage] = None):
        self.host = host
        self.port = port
        self.storage = storage or FirewallStorage()
        self.server: Optional[ThreadedWebServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        FirewallRequestHandler.storage = self.storage
        self.server = ThreadedWebServer((self.host, self.port), FirewallRequestHandler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        print(f"[*] Web Radar UI active on http://{self.host}:{self.port}")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("[*] Web Radar UI stopped.")
