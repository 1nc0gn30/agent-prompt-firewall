"""
cli.py - Command Line Interface for Agent Prompt Firewall.
Zero external dependencies (Python 3.10+ standard library).
Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

from .detector import ThreatDetector
from .mcp_server import run_mcp_server
from .proxy import ProxyService
from .redactor import Redactor
from .server import WebRadarServer
from .storage import FirewallStorage

VERSION = "2.6.0"


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def cmd_serve(args: argparse.Namespace):
    web_port = args.web_port
    proxy_port = args.proxy_port
    db_path = args.db
    upstream = args.upstream
    threshold = args.threshold

    storage = FirewallStorage(db_path=db_path)

    print("=" * 68)
    print(f"  AGENT PROMPT FIREWALL v{VERSION} • Autonomous Inline Security Proxy")
    print("  Real-Time Prompt Injection Defense & Data Leak Prevention")
    print("=" * 68)

    host = args.host
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[!] WARNING: binding to {host} exposes the proxy and radar to your network.")
    web_server = WebRadarServer(
        host=host,
        port=web_port,
        storage=storage,
        proxy_port=proxy_port,
        block_threshold=threshold,
    )
    proxy_service = ProxyService(
        host=host,
        port=proxy_port,
        storage=storage,
        upstream_url=upstream,
        block_threshold=threshold,
    )

    try:
        web_server.start()
        proxy_service.start()
        print(f"[*] Web Radar UI:        http://{host}:{web_port}/")
        print(f"[*] Inline Proxy:        http://{host}:{proxy_port}/")
        print(f"[*] Intercepted Base:    http://{host}:{proxy_port}/v1")
        print(f"[*] Block Threshold:     {threshold:.2f}")
        if upstream:
            print(f"[*] Target Upstream:     {upstream}")
        else:
            print("[*] Target Upstream:     None (Autonomous Zero-Cost Mock Echo)")
        print("-" * 68)
        print("Press Ctrl+C to stop services.")
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Shutting down Agent Prompt Firewall...")
    finally:
        web_server.stop()
        proxy_service.stop()


def cmd_scan(args: argparse.Namespace):
    prompt = args.text if getattr(args, "text", None) is not None else args.prompt
    if prompt is None:
        print("Error: Provide prompt text positionally or via --text.", file=sys.stderr)
        sys.exit(2)

    detector = ThreatDetector(block_threshold=args.threshold)
    redactor = Redactor()

    start = time.perf_counter()
    assessment = detector.evaluate(prompt)
    redaction = redactor.redact(prompt)
    assessment.details = [redactor.redact(d).redacted_text for d in assessment.details]
    duration_ms = round((time.perf_counter() - start) * 1000, 2)

    if getattr(args, "json", False):
        print(json.dumps({
            "version": VERSION,
            "blocked": assessment.should_block,
            "threshold": args.threshold,
            "threat": assessment.to_dict(),
            "redaction": redaction.to_dict(),
            "sanitized_prompt": redaction.redacted_text,
            "duration_ms": duration_ms,
        }, indent=2))
        return

    print("=" * 60)
    print(f"  AGENT PROMPT FIREWALL v{VERSION} • THREAT SCAN REPORT")
    print("=" * 60)
    print(f"Threat Score:          {assessment.score:.2f} / 1.00")
    print(f"Threat Classification: {assessment.threat_type}")
    print(f"Block Decision:        {'BLOCKED' if assessment.should_block else 'PERMITTED'}")
    print(f"Latency:               {duration_ms:.2f}ms")
    print(f"Shannon Entropy:       {assessment.entropy:.2f} bits/symbol")

    if assessment.categories:
        print(f"Categories Detected:   {', '.join(assessment.categories)}")
    if assessment.details:
        print("Threat Details:")
        for d in assessment.details:
            print(f"  • {d}")

    print("-" * 60)
    print(f"Secrets / PII Redacted: {redaction.redacted_count}")
    if redaction.findings:
        for f in redaction.findings:
            print(f"  • [{f['type']}] -> {f['placeholder']}")

    print("-" * 60)
    print("Sanitized Prompt:")
    print(redaction.redacted_text)
    print("=" * 60)


def cmd_stats(args: argparse.Namespace):
    port = getattr(args, "port", 8098)
    as_json = bool(getattr(args, "json", False))
    live_health = None
    live_stats = None
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2.0) as resp:
            live_health = json.loads(resp.read().decode("utf-8"))
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/stats", timeout=2.0) as resp:
            live_stats = json.loads(resp.read().decode("utf-8"))
    except Exception:
        pass

    storage = FirewallStorage(db_path=args.db)
    stats = live_stats if live_stats is not None else storage.get_stats()
    chain = storage.verify_chain()

    if as_json:
        print(json.dumps({
            "service": "agent-prompt-firewall",
            "version": VERSION,
            "online": live_health is not None,
            "web_port": port,
            "proxy_port": live_health.get("proxy_port", 8198) if live_health else 8198,
            "health": live_health,
            "stats": stats,
            "chain_verification": chain,
        }, indent=2))
        return

    print("=" * 60)
    print(f"  AGENT PROMPT FIREWALL v{VERSION} • TELEMETRY STATS")
    print("=" * 60)
    print(f"Daemon Endpoint:       http://127.0.0.1:{port} ({'ONLINE' if live_health else 'LOCAL DB'})")
    print(f"Inline Proxy Port:     {live_health.get('proxy_port', 8198) if live_health else 8198}")
    print(f"Total Prompts Scanned: {stats.get('total_scans', 0)}")
    print(f"Threats Blocked:       {stats.get('total_blocked', 0)}")
    print(f"Secrets/PII Redacted:  {stats.get('total_redactions', 0)}")
    print(f"Clean Traffic Rate:    {stats.get('clean_rate', 100.0)}%")
    print(f"Average Latency:       {stats.get('avg_latency_ms', 0.0)}ms")
    print(f"Audit Chain Valid:     {'YES' if chain.get('valid') else 'TAMPERED'} ({chain.get('verified_entries', 0)} entries)")

    breakdown = stats.get("threat_breakdown", {})
    if breakdown:
        print("\nThreat Distribution:")
        for t_type, count in breakdown.items():
            print(f"  • {t_type.ljust(10)}: {count}")
    print("=" * 60)


def cmd_mcp(args: argparse.Namespace):
    run_mcp_server(db_path=args.db, web_port=args.port, block_threshold=args.threshold)


def cmd_run(args: argparse.Namespace):
    if not args.cmd:
        print("Error: No command specified to run. Usage: agent-firewall run -- <command>")
        sys.exit(1)

    web_port = args.web_port
    proxy_port = args.proxy_port
    storage = FirewallStorage(db_path=args.db)

    proxy_was_running = is_port_in_use(proxy_port)
    web_server = None
    proxy_service = None

    if not proxy_was_running:
        print(f"[*] Starting local Firewall Proxy on port {proxy_port}...")
        web_server = WebRadarServer(host="127.0.0.1", port=web_port, storage=storage, proxy_port=proxy_port)
        proxy_service = ProxyService(host="127.0.0.1", port=proxy_port, storage=storage, upstream_url=args.upstream)
        web_server.start()
        proxy_service.start()
        time.sleep(0.3)
    else:
        print(f"[*] Connected to existing Firewall Proxy on port {proxy_port}")

    env = os.environ.copy()
    proxy_base_v1 = f"http://127.0.0.1:{proxy_port}/v1"
    proxy_base = f"http://127.0.0.1:{proxy_port}"
    env["OPENAI_BASE_URL"] = proxy_base_v1
    env["ANTHROPIC_BASE_URL"] = proxy_base
    env["HTTP_PROXY"] = proxy_base
    env["http_proxy"] = proxy_base

    print(f"[*] [Firewall Active] Intercepting LLM requests on port {proxy_port}")
    print(f"[*] OPENAI_BASE_URL    -> {proxy_base_v1}")
    print(f"[*] ANTHROPIC_BASE_URL -> {proxy_base}")
    print(f"[*] Executing child process: {' '.join(args.cmd)}\n")

    start_time = time.perf_counter()
    exit_code = 0
    try:
        proc = subprocess.run(args.cmd, env=env)
        exit_code = proc.returncode
    except KeyboardInterrupt:
        print("\n[*] Process terminated by user.")
        exit_code = 130
    finally:
        total_time = round(time.perf_counter() - start_time, 2)
        if not proxy_was_running:
            if web_server:
                web_server.stop()
            if proxy_service:
                proxy_service.stop()

    print("\n" + "=" * 60)
    print(f"  AGENT PROMPT FIREWALL v{VERSION} • RUN SESSION REPORT")
    print("=" * 60)
    print(f"  Session Duration:      {total_time}s")
    print(f"  Child Exit Code:       {exit_code}")
    print("=" * 60)
    sys.exit(exit_code)


def cmd_test(args: argparse.Namespace):
    """Run pytest test suite."""
    print("=" * 60)
    print(f"  AGENT PROMPT FIREWALL v{VERSION} • RUNNING TEST SUITE")
    print("=" * 60)
    test_cmd = [sys.executable, "-m", "pytest", "tests/"]
    if getattr(args, "verbose", False):
        test_cmd.append("-v")
    if getattr(args, "pytest_args", None):
        test_cmd.extend(args.pytest_args)
    res = subprocess.run(test_cmd)
    sys.exit(res.returncode)


def main():
    parser = argparse.ArgumentParser(
        prog="agent-prompt-firewall",
        description="Autonomous Zero-Dependency Security Proxy, Threat Radar & MCP Server for AI Agents",
    )
    parser.add_argument("--version", action="version", version=f"agent-prompt-firewall {VERSION}")
    parser.add_argument("--status", action="store_true", help="View firewall daemon status and telemetry")
    parser.add_argument("--json", action="store_true", help="Emit telemetry in structured JSON")
    parser.add_argument("--port", type=int, default=8098, help="Web UI dashboard port (default: 8098)")
    parser.add_argument("--db", default="firewall.db", help="SQLite database path")
    subparsers = parser.add_subparsers(dest="subcommand", required=False)

    # serve
    p_serve = subparsers.add_parser("serve", help="Launch Web Radar UI (:8098) and Inline Proxy (:8198)")
    p_serve.add_argument("--web-port", "--port", dest="web_port", type=int, default=8098, help="Web UI dashboard port (default: 8098)")
    p_serve.add_argument("--proxy-port", type=int, default=8198, help="Inline proxy port (default: 8198)")
    p_serve.add_argument("--db", default="firewall.db", help="SQLite database path")
    p_serve.add_argument("--upstream", default=None, help="Upstream LLM target URL (optional)")
    p_serve.add_argument("--threshold", type=float, default=0.70, help="Threat blocking threshold (default: 0.70)")
    p_serve.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    p_serve.set_defaults(func=cmd_serve)

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan a prompt for injection attacks and sensitive data")
    p_scan.add_argument("prompt", nargs="?", default=None, help="Prompt text to analyze")
    p_scan.add_argument("--text", default=None, help="Prompt text to analyze (flag form)")
    p_scan.add_argument("--threshold", type=float, default=0.70, help="Threat blocking threshold (0.05 to 0.99)")
    p_scan.add_argument("--json", action="store_true", help="Output scan verdict as JSON")
    p_scan.set_defaults(func=cmd_scan)

    # stats
    p_stats = subparsers.add_parser("stats", help="View aggregated firewall telemetry")
    p_stats.add_argument("--db", default="firewall.db", help="SQLite database path")
    p_stats.add_argument("--port", type=int, default=8098, help="Web UI dashboard port (default: 8098)")
    p_stats.add_argument("--json", action="store_true", help="Emit telemetry in structured JSON")
    p_stats.set_defaults(func=cmd_stats)

    # status
    p_status = subparsers.add_parser("status", help="View firewall daemon status and telemetry")
    p_status.add_argument("--db", default="firewall.db", help="SQLite database path")
    p_status.add_argument("--port", type=int, default=8098, help="Web UI dashboard port (default: 8098)")
    p_status.add_argument("--json", action="store_true", help="Emit telemetry in structured JSON")
    p_status.set_defaults(func=cmd_stats)

    # mcp
    p_mcp = subparsers.add_parser("mcp", help="Run JSON-RPC 2.0 stdio MCP server (4 live tools)")
    p_mcp.add_argument("--db", default="firewall.db", help="SQLite database path")
    p_mcp.add_argument("--port", type=int, default=8098, help="Web UI dashboard port (default: 8098)")
    p_mcp.add_argument("--threshold", type=float, default=0.70, help="Default threat blocking threshold")
    p_mcp.set_defaults(func=cmd_mcp)

    # run
    p_run = subparsers.add_parser("run", help="Execute an agent command with transparent firewall interception")
    p_run.add_argument("--web-port", type=int, default=8098, help="Web UI dashboard port (default: 8098)")
    p_run.add_argument("--proxy-port", type=int, default=8198, help="Inline proxy port (default: 8198)")
    p_run.add_argument("--db", default="firewall.db", help="SQLite database path")
    p_run.add_argument("--upstream", default=None, help="Upstream LLM target URL (optional)")
    p_run.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run (prefixed by --)")
    p_run.set_defaults(func=cmd_run)

    # test
    p_test = subparsers.add_parser("test", help="Execute firewall test suite via pytest")
    p_test.add_argument("-v", "--verbose", action="store_true", help="Verbose pytest output")
    p_test.add_argument("pytest_args", nargs=argparse.REMAINDER, help="Additional arguments forwarded to pytest")
    p_test.set_defaults(func=cmd_test)

    parsed = parser.parse_args()
    if getattr(parsed, "status", False) or (getattr(parsed, "json", False) and not parsed.subcommand):
        cmd_stats(parsed)
        return
    if not parsed.subcommand:
        parser.print_help()
        return
    if hasattr(parsed, "cmd") and parsed.cmd and parsed.cmd[0] == "--":
        parsed.cmd = parsed.cmd[1:]

    parsed.func(parsed)


if __name__ == "__main__":
    main()
