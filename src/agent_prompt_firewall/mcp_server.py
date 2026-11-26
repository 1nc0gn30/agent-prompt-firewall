"""
mcp_server.py - Zero-Dependency JSON-RPC 2.0 Stdio MCP Server for Agent Prompt Firewall.
Exposes 4 live tools:
  - prompt_firewall_scan
  - prompt_firewall_redact
  - prompt_firewall_stats
  - prompt_firewall_threats
Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
"""

import json
import sys
import time
import urllib.request
from typing import Any, Dict, List, Optional, TextIO

from .detector import ThreatDetector
from .redactor import Redactor
from .storage import FirewallStorage

SERVER_NAME = "agent-prompt-firewall"
SERVER_VERSION = "2.6.0"
PROTOCOL_VERSION = "2024-11-05"

TOOLS: List[Dict[str, Any]] = [
    {
        "name": "prompt_firewall_scan",
        "description": "Scan a prompt for direct/indirect prompt injection, jailbreaks, obfuscation (homoglyphs, HTML entities, URL encoding, ROT13, leetspeak, Base64/zlib, hex), and scrub secrets/PII.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string", "description": "Raw prompt text to inspect and redact"},
                "threshold": {"type": "number", "minimum": 0.05, "maximum": 0.99, "default": 0.70, "description": "Blocking threshold score (0.05-0.99)"},
                "log_to_db": {"type": "boolean", "default": False, "description": "Persist redacted verdict to local SQLite audit ledger"},
            },
            "required": ["prompt"],
        },
    },
    {
        "name": "prompt_firewall_redact",
        "description": "Scrub API keys (OpenAI, Anthropic, AWS, Google, GitHub, Stripe), PEM private keys, database URLs, SSNs, Luhn-valid credit cards, emails, and phone numbers.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to scrub for secrets and PII"},
            },
            "required": ["text"],
        },
    },
    {
        "name": "prompt_firewall_stats",
        "description": "Return aggregated firewall telemetry (total scans, blocked count, redactions, clean rate, and SHA-256 audit chain integrity) from the live daemon or local SQLite DB.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "port": {"type": "integer", "default": 8098, "description": "Web Radar loopback port to query first"},
            },
        },
    },
    {
        "name": "prompt_firewall_threats",
        "description": "List recent blocked or high-severity threat events (redacted previews only) from the live daemon or local SQLite DB.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20, "description": "Maximum number of recent threat events"},
                "port": {"type": "integer", "default": 8098, "description": "Web Radar loopback port to query first"},
            },
        },
    },
]


def _fetch_local_json(url: str, timeout: float = 1.5) -> Optional[Any]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None
    return None


class PromptFirewallMCPServer:
    def __init__(self, db_path: str = "firewall.db", web_port: int = 8098, block_threshold: float = 0.70):
        self.db_path = db_path
        self.web_port = web_port
        self.detector = ThreatDetector(block_threshold=block_threshold)
        self.redactor = Redactor()
        self._storage: Optional[FirewallStorage] = None

    def _get_storage(self) -> FirewallStorage:
        if self._storage is None:
            self._storage = FirewallStorage(db_path=self.db_path)
        return self._storage

    def _call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if name == "prompt_firewall_scan":
            prompt = arguments.get("prompt")
            if not isinstance(prompt, str):
                raise ValueError("'prompt' must be a string")
            threshold = arguments.get("threshold", self.detector.block_threshold)
            if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not (0.05 <= float(threshold) <= 0.99):
                raise ValueError("'threshold' must be a number between 0.05 and 0.99")
            t0 = time.perf_counter()
            assessment = self.detector.evaluate(prompt, threshold=float(threshold))
            redaction = self.redactor.redact(prompt)
            assessment.details = [self.redactor.redact(d).redacted_text for d in assessment.details]
            duration_ms = round((time.perf_counter() - t0) * 1000, 2)
            scan_id = 0
            if arguments.get("log_to_db"):
                scan_id = self._get_storage().log_scan({
                    "direction": "mcp",
                    "prompt_snippet": redaction.redacted_text[:180],
                    "threat_score": assessment.score,
                    "threat_type": assessment.threat_type,
                    "categories": assessment.categories,
                    "details": assessment.details,
                    "blocked": assessment.should_block,
                    "redacted_count": redaction.redacted_count,
                    "findings": redaction.findings,
                    "duration_ms": duration_ms,
                    "source_ip": "127.0.0.1",
                })
            return {
                "scan_id": scan_id,
                "blocked": assessment.should_block,
                "threshold": float(threshold),
                "threat": assessment.to_dict(),
                "redaction": redaction.to_dict(),
                "sanitized_prompt": redaction.redacted_text,
                "duration_ms": duration_ms,
            }

        if name == "prompt_firewall_redact":
            text = arguments.get("text")
            if not isinstance(text, str):
                raise ValueError("'text' must be a string")
            return self.redactor.redact(text).to_dict()

        if name == "prompt_firewall_stats":
            port = int(arguments.get("port", self.web_port))
            live_stats = _fetch_local_json(f"http://127.0.0.1:{port}/api/stats")
            if live_stats is not None:
                return {"source": f"live_daemon:{port}", "version": SERVER_VERSION, "stats": live_stats}
            storage = self._get_storage()
            return {
                "source": "local_sqlite",
                "version": SERVER_VERSION,
                "stats": storage.get_stats(),
                "chain_verification": storage.verify_chain(),
            }

        if name == "prompt_firewall_threats":
            port = int(arguments.get("port", self.web_port))
            limit = max(1, min(200, int(arguments.get("limit", 20))))
            live_threats = _fetch_local_json(f"http://127.0.0.1:{port}/api/threats?limit={limit}")
            if live_threats is not None:
                return {"source": f"live_daemon:{port}", "count": len(live_threats), "threats": live_threats}
            threats = self._get_storage().get_recent_threats(limit=limit)
            return {"source": "local_sqlite", "count": len(threats), "threats": threats}

        raise KeyError(f"Unknown tool: {name}")

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        req_id = req.get("id")
        method = req.get("method", "")
        params = req.get("params") or {}

        # Notifications have no id and expect no response
        if req_id is None and method.startswith("notifications/"):
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}

        if method == "tools/call":
            tool_name = params.get("name")
            tool_args = params.get("arguments") or {}
            if not isinstance(tool_args, dict):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Tool arguments must be a JSON object"},
                }
            try:
                result = self._call_tool(str(tool_name), tool_args)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                        "structuredContent": result,
                        "isError": False,
                    },
                }
            except KeyError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": str(exc)},
                }
            except Exception as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": json.dumps({"error": str(exc)})}],
                        "isError": True,
                    },
                }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def run_mcp_server(
    db_path: str = "firewall.db",
    web_port: int = 8098,
    block_threshold: float = 0.70,
    stdin: Optional[TextIO] = None,
    stdout: Optional[TextIO] = None,
):
    """Run line-delimited JSON-RPC 2.0 MCP server over stdio."""
    in_stream = stdin or sys.stdin
    out_stream = stdout or sys.stdout
    server = PromptFirewallMCPServer(db_path=db_path, web_port=web_port, block_threshold=block_threshold)

    for raw_line in in_stream:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            out_stream.write(json.dumps(err_resp) + "\n")
            out_stream.flush()
            continue

        if not isinstance(req, dict):
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid JSON-RPC request"},
            }
            out_stream.write(json.dumps(err_resp) + "\n")
            out_stream.flush()
            continue

        resp = server.handle_request(req)
        if resp is not None:
            out_stream.write(json.dumps(resp) + "\n")
            out_stream.flush()
