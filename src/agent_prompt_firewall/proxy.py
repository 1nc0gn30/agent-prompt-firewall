"""
proxy.py - Transparent Inline Security Proxy for AI Agents.
Listens on port 8099, intercepts LLM calls, detects threats, and redacts PII/secrets.
Zero external dependencies (Python 3.10+ standard library).
"""

import json
import os
import re
import socket
import threading
import time
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Optional, Dict, Any, List, Tuple

from .detector import ThreatDetector, ThreatAssessment
from .redactor import Redactor, RedactionResult
from .storage import FirewallStorage, GLOBAL_BROADCASTER


class ThreadedProxyServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class ProxyRequestHandler(BaseHTTPRequestHandler):
    storage: FirewallStorage = None
    detector: ThreatDetector = ThreatDetector(block_threshold=0.70)
    redactor: Redactor = Redactor()
    upstream_url: Optional[str] = None

    def log_message(self, format, *args):
        # Silence default stderr request noise in tests/production
        pass

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("x-firewall-inspected", "true")
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        if self.path in ("/health", "/v1/health", "/"):
            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "status": "online",
                "service": "agent-prompt-firewall-proxy",
                "version": "0.1.0",
                "port": 8099
            }).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        start_time = time.perf_counter()
        content_length = int(self.headers.get("Content-Length", 0))
        raw_body = self.rfile.read(content_length) if content_length > 0 else b""
        
        # Parse payload
        body_text = raw_body.decode("utf-8", errors="ignore")
        is_json = False
        payload: Dict[str, Any] = {}
        try:
            payload = json.loads(body_text) if body_text else {}
            is_json = True
        except Exception:
            payload = {"raw": body_text}

        # Extract text components to scan
        extracted_texts: List[str] = []
        if isinstance(payload, dict):
            # OpenAI / Anthropic messages
            if "messages" in payload and isinstance(payload["messages"], list):
                for m in payload["messages"]:
                    if isinstance(m, dict):
                        content = m.get("content", "")
                        if isinstance(content, str):
                            extracted_texts.append(content)
                        elif isinstance(content, list):
                            for block in content:
                                if isinstance(block, dict) and "text" in block:
                                    extracted_texts.append(block["text"])
            if "prompt" in payload:
                p = payload["prompt"]
                if isinstance(p, str):
                    extracted_texts.append(p)
                elif isinstance(p, list):
                    extracted_texts.extend([str(x) for x in p])
            if "system" in payload and isinstance(payload["system"], str):
                extracted_texts.append(payload["system"])
            if "input" in payload and isinstance(payload["input"], str):
                extracted_texts.append(payload["input"])

        if not extracted_texts and body_text:
            extracted_texts.append(body_text)

        combined_input = "\n\n".join(extracted_texts)

        # 1. Threat Detection
        assessment = self.detector.evaluate(combined_input)
        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        source_ip = self.client_address[0] if self.client_address else "127.0.0.1"

        # 2. If blocked, reject immediately
        if assessment.should_block:
            scan_id = 0
            if self.storage:
                scan_id = self.storage.log_scan({
                    "direction": "inbound",
                    "prompt_snippet": combined_input[:180],
                    "threat_score": assessment.score,
                    "threat_type": assessment.threat_type,
                    "categories": assessment.categories,
                    "details": assessment.details,
                    "blocked": True,
                    "redacted_count": 0,
                    "findings": [],
                    "duration_ms": elapsed_ms,
                    "source_ip": source_ip,
                })
            
            event_payload = {
                "id": scan_id,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_score": assessment.score,
                "score": assessment.score,
                "threat_type": assessment.threat_type,
                "redacted_count": 0,
                "blocked": True,
                "action": "BLOCKED",
                "source": "proxy:8099",
                "details": assessment.details,
                "snippet": combined_input[:120],
                "latency_ms": elapsed_ms,
            }
            GLOBAL_BROADCASTER.broadcast("threat_event", event_payload)

            self.send_response(403)
            self._set_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.send_header("x-firewall-action", "blocked")
            self.send_header("x-threat-score", str(assessment.score))
            self.send_header("x-threat-type", assessment.threat_type)
            self.end_headers()

            error_body = {
                "error": {
                    "message": f"Request blocked by Agent Prompt Firewall: {'; '.join(assessment.details)}",
                    "type": "prompt_injection_violation",
                    "param": None,
                    "code": "firewall_threat_blocked",
                    "threat_score": assessment.score,
                    "threat_type": assessment.threat_type,
                    "categories": assessment.categories
                }
            }
            self.wfile.write(json.dumps(error_body, indent=2).encode("utf-8"))
            return

        # 3. Redact Secrets & PII in payload
        redacted_findings: List[Dict[str, Any]] = []
        total_redacted = 0

        def scrub_recursive(obj: Any) -> Any:
            nonlocal total_redacted
            if isinstance(obj, str):
                res = self.redactor.redact(obj)
                if res.redacted_count > 0:
                    total_redacted += res.redacted_count
                    redacted_findings.extend(res.findings)
                    return res.redacted_text
                return obj
            elif isinstance(obj, list):
                return [scrub_recursive(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: scrub_recursive(v) for k, v in obj.items()}
            return obj

        sanitized_payload = scrub_recursive(payload) if is_json else payload
        sanitized_body = json.dumps(sanitized_payload).encode("utf-8") if is_json else self.redactor.redact(body_text).redacted_text.encode("utf-8")

        # 4. Route or Mock
        upstream = self.headers.get("x-target-url") or self.upstream_url or os.environ.get("FIREWALL_UPSTREAM")
        resp_body: bytes = b""
        resp_status = 200

        if upstream:
            # Forward to upstream
            target_url = f"{upstream.rstrip('/')}{self.path}"
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length")}
            headers["Host"] = urllib.parse.urlparse(target_url).netloc
            try:
                req = urllib.request.Request(target_url, data=sanitized_body, headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=30.0) as u_resp:
                    resp_status = u_resp.status
                    raw_resp = u_resp.read()
                    # Inspect outbound response for leaked secrets / PII
                    resp_text = raw_resp.decode("utf-8", errors="ignore")
                    outbound_redaction = self.redactor.redact(resp_text)
                    if outbound_redaction.redacted_count > 0:
                        total_redacted += outbound_redaction.redacted_count
                        redacted_findings.extend(outbound_redaction.findings)
                        resp_body = outbound_redaction.redacted_text.encode("utf-8")
                    else:
                        resp_body = raw_resp
            except urllib.error.HTTPError as e:
                resp_status = e.code
                resp_body = e.read()
            except Exception as e:
                resp_status = 502
                resp_body = json.dumps({"error": f"Upstream connection failed: {str(e)}"}).encode("utf-8")
        else:
            # Offline Mock Response
            model = payload.get("model", "agent-firewall-sanitized") if is_json else "model"
            if "/v1/messages" in self.path:
                mock_data = {
                    "id": f"msg_fw_{int(time.time())}",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Prompt inspected and sanitized by Agent Prompt Firewall. Zero threats detected."}],
                    "model": model,
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 20, "output_tokens": 15}
                }
            else:
                mock_data = {
                    "id": f"chatcmpl-fw-{int(time.time())}",
                    "object": "chat.completion",
                    "created": int(time.time()),
                    "model": model,
                    "choices": [{
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Prompt inspected and sanitized by Agent Prompt Firewall. Zero threats detected."
                        },
                        "finish_reason": "stop"
                    }],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 15, "total_tokens": 35}
                }
            resp_body = json.dumps(mock_data, indent=2).encode("utf-8")

        total_latency = round((time.perf_counter() - start_time) * 1000, 2)

        # Log scan
        scan_id = 0
        if self.storage:
            scan_id = self.storage.log_scan({
                "direction": "inbound",
                "prompt_snippet": combined_input[:180],
                "threat_score": assessment.score,
                "threat_type": assessment.threat_type,
                "categories": assessment.categories,
                "details": assessment.details,
                "blocked": False,
                "redacted_count": total_redacted,
                "findings": redacted_findings,
                "duration_ms": total_latency,
                "source_ip": source_ip,
            })

        event_payload = {
            "id": scan_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "threat_score": assessment.score,
            "score": assessment.score,
            "threat_type": assessment.threat_type,
            "redacted_count": total_redacted,
            "blocked": False,
            "action": "PASSED",
            "source": "proxy:8099",
            "details": assessment.details,
            "snippet": combined_input[:120],
            "latency_ms": total_latency,
        }
        GLOBAL_BROADCASTER.broadcast("threat_event", event_payload)

        self.send_response(resp_status)
        self._set_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("x-firewall-action", "passed")
        self.send_header("x-firewall-inspected", "true")
        self.send_header("x-threat-score", str(assessment.score))
        self.send_header("x-threat-type", assessment.threat_type)
        self.send_header("x-redacted-count", str(total_redacted))
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)

    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Expose-Headers", "x-firewall-action, x-firewall-inspected, x-threat-score, x-threat-type, x-redacted-count")


class ProxyService:
    """Manager for the background ThreadedProxyServer."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8099, storage: Optional[FirewallStorage] = None, upstream_url: Optional[str] = None):
        self.host = host
        self.port = port
        self.storage = storage or FirewallStorage()
        self.upstream_url = upstream_url
        self.server: Optional[ThreadedProxyServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        ProxyRequestHandler.storage = self.storage
        ProxyRequestHandler.upstream_url = self.upstream_url
        self.server = ThreadedProxyServer((self.host, self.port), ProxyRequestHandler)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        print(f"[*] Proxy Service active on http://{self.host}:{self.port}")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("[*] Proxy Service stopped.")
