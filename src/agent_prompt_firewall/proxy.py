"""
proxy.py - Transparent Inline Security Proxy for AI Agents.
Listens on port 8198, intercepts LLM calls, detects inbound/outbound threats,
and redacts PII/secrets before persistence or forwarding.
Zero external dependencies (Python 3.10+ standard library).
Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
"""

import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from typing import Optional, Dict, Any, List

from .detector import ThreatDetector
from .redactor import Redactor
from .security import (
    MAX_BODY_BYTES,
    NoRedirectHandler,
    cors_origin_for,
    is_local_host,
    is_local_origin,
    read_request_body,
    validate_upstream_url,
)
from .storage import FirewallStorage, GLOBAL_BROADCASTER

VERSION = "2.6.0"

# Backwards-compatible exports for tests
_is_local_origin = is_local_origin


def _cors_origin(handler) -> Optional[str]:
    return cors_origin_for(handler)


class ThreadedProxyServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class ProxyRequestHandler(BaseHTTPRequestHandler):
    storage: Optional[FirewallStorage] = None
    detector: ThreatDetector = ThreatDetector(block_threshold=0.70)
    redactor: Redactor = Redactor()
    upstream_url: Optional[str] = None

    def log_message(self, format, *args):
        pass

    def _send_json(
        self,
        status: int,
        payload: Any,
        extra_headers: Optional[Dict[str, str]] = None,
        include_cors: bool = True,
    ):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        if include_cors:
            self._set_cors_headers()
        else:
            self.send_header("Vary", "Origin")
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _enforce_guards(self) -> bool:
        """Enforce strict Host (DNS rebinding) and Origin (CSRF) guards.
        Returns True if request is permitted to proceed."""
        if not is_local_host(self.headers.get("Host")):
            self._send_json(403, {"error": "forbidden host header"}, include_cors=False)
            return False
        origin = self.headers.get("Origin")
        if origin and not is_local_origin(origin):
            self._send_json(403, {"error": "cross-origin request blocked"}, include_cors=False)
            return False
        return True

    def _set_cors_headers(self):
        self.send_header("Vary", "Origin")
        allowed = cors_origin_for(self)
        if allowed:
            self.send_header("Access-Control-Allow-Origin", allowed)
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, HEAD")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-api-key, x-target-url")
        self.send_header(
            "Access-Control-Expose-Headers",
            "x-firewall-action, x-firewall-inspected, x-threat-score, x-threat-type, x-redacted-count",
        )

    def do_HEAD(self):
        if not self._enforce_guards():
            return
        path = self.path.split("?")[0]
        if path in ("/health", "/v1/health", "/"):
            self.send_response(200)
            self._set_cors_headers()
            self.send_header("x-firewall-inspected", "true")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            return
        self.send_response(404)
        self._set_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def do_OPTIONS(self):
        if not self._enforce_guards():
            return
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        if not self._enforce_guards():
            return
        path = self.path.split("?")[0]
        if path in ("/health", "/v1/health", "/"):
            self._send_json(200, {
                "status": "online",
                "service": "agent-prompt-firewall-proxy",
                "version": VERSION,
                "port": self.server.server_port,
            })
            return

        self._send_json(404, {"error": f"Endpoint not found: {path}"})

    def do_POST(self):
        if not self._enforce_guards():
            return

        start_time = time.perf_counter()
        raw_body, err = read_request_body(self, MAX_BODY_BYTES)
        if err is not None:
            status_code, message = err
            self._send_json(status_code, {"error": message})
            return

        body_text = (raw_body or b"").decode("utf-8", errors="ignore")
        content_type = (self.headers.get("Content-Type") or "").lower()
        is_json = False
        payload: Dict[str, Any] = {}

        if body_text:
            wants_json = ("application/json" in content_type) or body_text.lstrip().startswith(("{", "["))
            if wants_json:
                try:
                    parsed = json.loads(body_text)
                except json.JSONDecodeError:
                    self._send_json(400, {"error": "Malformed JSON request body"})
                    return
                if not isinstance(parsed, dict):
                    self._send_json(400, {"error": "JSON payload must be a JSON object"})
                    return
                payload = parsed
                is_json = True
            else:
                payload = {"raw": body_text}

        # Extract text components to scan with strict type validation
        extracted_texts: List[str] = []
        if is_json:
            if "messages" in payload:
                msgs = payload["messages"]
                if not isinstance(msgs, list):
                    self._send_json(400, {"error": "'messages' must be an array"})
                    return
                for m in msgs:
                    if not isinstance(m, dict):
                        self._send_json(400, {"error": "Each item in 'messages' must be an object"})
                        return
                    content = m.get("content", "")
                    if isinstance(content, str):
                        extracted_texts.append(content)
                    elif isinstance(content, list):
                        for block in content:
                            if not isinstance(block, dict):
                                self._send_json(400, {"error": "Each content block must be an object"})
                                return
                            if "text" in block:
                                if not isinstance(block["text"], str):
                                    self._send_json(400, {"error": "Content block 'text' must be a string"})
                                    return
                                extracted_texts.append(block["text"])
                    elif content is not None:
                        self._send_json(400, {"error": "Message 'content' must be a string or list"})
                        return

            if "prompt" in payload:
                p = payload["prompt"]
                if isinstance(p, str):
                    extracted_texts.append(p)
                elif isinstance(p, list) and all(isinstance(x, str) for x in p):
                    extracted_texts.extend(p)
                else:
                    self._send_json(400, {"error": "'prompt' must be a string or list of strings"})
                    return

            if "system" in payload:
                if not isinstance(payload["system"], str):
                    self._send_json(400, {"error": "'system' must be a string"})
                    return
                extracted_texts.append(payload["system"])

            if "input" in payload:
                if not isinstance(payload["input"], str):
                    self._send_json(400, {"error": "'input' must be a string"})
                    return
                extracted_texts.append(payload["input"])

        if not extracted_texts and body_text:
            extracted_texts.append(body_text)

        combined_input = "\n\n".join(extracted_texts)

        # 1. Threat Detection & Pre-Storage Secret Redaction
        assessment = self.detector.evaluate(combined_input)
        pre_redaction = self.redactor.redact(combined_input)
        safe_snippet = pre_redaction.redacted_text
        safe_details = [self.redactor.redact(d).redacted_text for d in assessment.details]

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
        source_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        proxy_source = f"proxy:{self.server.server_port}"

        # 2. If blocked, reject immediately (persist & broadcast ONLY redacted snippets)
        if assessment.should_block:
            scan_id = 0
            if self.storage:
                scan_id = self.storage.log_scan({
                    "direction": "inbound",
                    "prompt_snippet": safe_snippet[:180],
                    "threat_score": assessment.score,
                    "threat_type": assessment.threat_type,
                    "categories": assessment.categories,
                    "details": safe_details,
                    "blocked": True,
                    "redacted_count": pre_redaction.redacted_count,
                    "findings": pre_redaction.findings,
                    "duration_ms": elapsed_ms,
                    "source_ip": source_ip,
                })

            event_payload = {
                "id": scan_id,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_score": assessment.score,
                "score": assessment.score,
                "threat_type": assessment.threat_type,
                "redacted_count": pre_redaction.redacted_count,
                "blocked": True,
                "action": "BLOCKED",
                "source": proxy_source,
                "details": safe_details,
                "snippet": safe_snippet[:120],
                "latency_ms": elapsed_ms,
            }
            GLOBAL_BROADCASTER.broadcast("threat_event", event_payload)

            error_body = {
                "error": {
                    "message": f"Request blocked by Agent Prompt Firewall: {'; '.join(safe_details)}",
                    "type": "prompt_injection_violation",
                    "param": None,
                    "code": "firewall_threat_blocked",
                    "threat_score": assessment.score,
                    "threat_type": assessment.threat_type,
                    "categories": assessment.categories,
                }
            }
            self._send_json(
                403,
                error_body,
                extra_headers={
                    "x-firewall-action": "blocked",
                    "x-firewall-inspected": "true",
                    "x-threat-score": str(assessment.score),
                    "x-threat-type": assessment.threat_type,
                    "x-redacted-count": str(pre_redaction.redacted_count),
                },
            )
            return

        # 3. Redact Secrets & PII in payload (both JSON and plain-text payloads!)
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
            if isinstance(obj, list):
                return [scrub_recursive(item) for item in obj]
            if isinstance(obj, dict):
                return {k: scrub_recursive(v) for k, v in obj.items()}
            return obj

        if is_json:
            sanitized_payload = scrub_recursive(payload)
            sanitized_body = json.dumps(sanitized_payload).encode("utf-8")
        else:
            raw_red = self.redactor.redact(body_text)
            total_redacted += raw_red.redacted_count
            redacted_findings.extend(raw_red.findings)
            sanitized_body = raw_red.redacted_text.encode("utf-8")

        # 4. Route to validated upstream or offline mock
        upstream = self.upstream_url or os.environ.get("FIREWALL_UPSTREAM")
        override = self.headers.get("x-target-url")
        if override:
            if os.environ.get("FIREWALL_ALLOW_TARGET_OVERRIDE") == "1":
                upstream = override
            else:
                self._send_json(
                    403,
                    {"error": "x-target-url override disabled; set FIREWALL_ALLOW_TARGET_OVERRIDE=1 to enable"},
                )
                return

        resp_body: bytes = b""
        resp_status = 200
        outbound_blocked = False
        outbound_assessment = None

        if upstream:
            allow_loopback = os.environ.get("FIREWALL_ALLOW_LOCAL_UPSTREAM") == "1"
            valid_url, reason = validate_upstream_url(upstream, allow_loopback=allow_loopback)
            if not valid_url:
                self._send_json(403, {"error": f"Upstream blocked by SSRF policy: {reason}"})
                return

            target_url = f"{upstream.rstrip('/')}{self.path}"
            headers = {
                k: v
                for k, v in self.headers.items()
                if k.lower() not in ("host", "content-length", "x-target-url", "origin")
            }
            headers["Host"] = urllib.parse.urlparse(target_url).netloc
            opener = urllib.request.build_opener(NoRedirectHandler())
            try:
                req = urllib.request.Request(target_url, data=sanitized_body, headers=headers, method="POST")
                with opener.open(req, timeout=30.0) as u_resp:
                    resp_status = u_resp.status
                    raw_resp = u_resp.read(MAX_BODY_BYTES + 1)
                    if len(raw_resp) > MAX_BODY_BYTES:
                        resp_status = 502
                        resp_body = json.dumps({"error": "Upstream response exceeded maximum allowed size"}).encode("utf-8")
                    else:
                        resp_text = raw_resp.decode("utf-8", errors="ignore")
                        outbound_assessment = self.detector.evaluate(resp_text)
                        outbound_redaction = self.redactor.redact(resp_text)
                        if outbound_redaction.redacted_count > 0:
                            total_redacted += outbound_redaction.redacted_count
                            redacted_findings.extend(outbound_redaction.findings)
                        if outbound_assessment.should_block:
                            outbound_blocked = True
                            out_details = [self.redactor.redact(d).redacted_text for d in outbound_assessment.details]
                            resp_status = 403
                            resp_body = json.dumps({
                                "error": {
                                    "message": f"Outbound upstream response blocked (indirect prompt injection): {'; '.join(out_details)}",
                                    "type": "outbound_injection_violation",
                                    "code": "firewall_outbound_blocked",
                                    "threat_score": outbound_assessment.score,
                                    "threat_type": outbound_assessment.threat_type,
                                    "categories": outbound_assessment.categories,
                                }
                            }, indent=2).encode("utf-8")
                        elif outbound_redaction.redacted_count > 0:
                            resp_body = outbound_redaction.redacted_text.encode("utf-8")
                        else:
                            resp_body = raw_resp
            except urllib.error.HTTPError as e:
                resp_status = e.code
                raw_err = e.read(MAX_BODY_BYTES) if e.fp else b""
                err_text = raw_err.decode("utf-8", errors="ignore")
                err_red = self.redactor.redact(err_text)
                if err_red.redacted_count > 0:
                    total_redacted += err_red.redacted_count
                    redacted_findings.extend(err_red.findings)
                    resp_body = err_red.redacted_text.encode("utf-8")
                else:
                    resp_body = raw_err if raw_err else json.dumps({"error": str(e.reason)}).encode("utf-8")
            except Exception as e:
                resp_status = 502
                resp_body = json.dumps({"error": f"Upstream connection failed: {str(e)}"}).encode("utf-8")
        else:
            model = payload.get("model", "agent-firewall-sanitized") if is_json else "model"
            if "/v1/messages" in self.path:
                mock_data = {
                    "id": f"msg_fw_{int(time.time())}",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Prompt inspected and sanitized by Agent Prompt Firewall. Zero threats detected."}],
                    "model": model,
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 20, "output_tokens": 15},
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
                            "content": "Prompt inspected and sanitized by Agent Prompt Firewall. Zero threats detected.",
                        },
                        "finish_reason": "stop",
                    }],
                    "usage": {"prompt_tokens": 20, "completion_tokens": 15, "total_tokens": 35},
                }
            resp_body = json.dumps(mock_data, indent=2).encode("utf-8")

        total_latency = round((time.perf_counter() - start_time) * 1000, 2)
        final_assessment = outbound_assessment if outbound_blocked and outbound_assessment else assessment
        final_details = [self.redactor.redact(d).redacted_text for d in final_assessment.details]

        # Log scan (ONLY redacted snippet)
        scan_id = 0
        if self.storage:
            scan_id = self.storage.log_scan({
                "direction": "outbound" if outbound_blocked else "inbound",
                "prompt_snippet": safe_snippet[:180],
                "threat_score": final_assessment.score,
                "threat_type": final_assessment.threat_type,
                "categories": final_assessment.categories,
                "details": final_details,
                "blocked": outbound_blocked,
                "redacted_count": total_redacted,
                "findings": redacted_findings,
                "duration_ms": total_latency,
                "source_ip": source_ip,
            })

        event_payload = {
            "id": scan_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "threat_score": final_assessment.score,
            "score": final_assessment.score,
            "threat_type": final_assessment.threat_type,
            "redacted_count": total_redacted,
            "blocked": outbound_blocked,
            "action": "BLOCKED" if outbound_blocked else "PASSED",
            "source": proxy_source,
            "details": final_details,
            "snippet": safe_snippet[:120],
            "latency_ms": total_latency,
        }
        GLOBAL_BROADCASTER.broadcast("threat_event", event_payload)

        self.send_response(resp_status)
        self._set_cors_headers()
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("x-firewall-action", "blocked" if outbound_blocked else "passed")
        self.send_header("x-firewall-inspected", "true")
        self.send_header("x-threat-score", str(final_assessment.score))
        self.send_header("x-threat-type", final_assessment.threat_type)
        self.send_header("x-redacted-count", str(total_redacted))
        self.send_header("Content-Length", str(len(resp_body)))
        self.end_headers()
        self.wfile.write(resp_body)


class ProxyService:
    """Manager for the background ThreadedProxyServer."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8198,
        storage: Optional[FirewallStorage] = None,
        upstream_url: Optional[str] = None,
        block_threshold: float = 0.70,
    ):
        self.host = host
        self.port = port
        self.storage = storage or FirewallStorage()
        self.upstream_url = upstream_url
        self.block_threshold = block_threshold
        self.server: Optional[ThreadedProxyServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self):
        handler_cls = type(
            "BoundProxyRequestHandler",
            (ProxyRequestHandler,),
            {
                "storage": self.storage,
                "upstream_url": self.upstream_url,
                "detector": ThreatDetector(block_threshold=self.block_threshold),
                "redactor": Redactor(),
            },
        )
        self.server = ThreadedProxyServer((self.host, self.port), handler_cls)
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        print(f"[*] Proxy Service active on http://{self.host}:{self.port}")

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("[*] Proxy Service stopped.")
