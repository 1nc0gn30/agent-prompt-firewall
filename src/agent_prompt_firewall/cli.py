"""
cli.py - Command Line Interface for Agent Prompt Firewall.
Zero external dependencies (Python 3.10+ standard library).
"""

import argparse
import os
import socket
import subprocess
import sys
import time
from typing import List, Optional

from .detector import ThreatDetector
from .redactor import Redactor
from .storage import FirewallStorage
from .proxy import ProxyService
from .server import WebRadarServer


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((host, port)) == 0


def cmd_serve(args: argparse.Namespace):
    web_port = args.web_port
    proxy_port = args.proxy_port
    db_path = args.db
    upstream = args.upstream

    storage = FirewallStorage(db_path=db_path)
    
    print("=" * 68)
    print("  AGENT PROMPT FIREWALL • Autonomous Inline Security Proxy")
    print("  Real-Time Prompt Injection Defense & Data Leak Prevention")
    print("=" * 68)

    host = args.host
    if host not in ("127.0.0.1", "localhost", "::1"):
        print(f"[!] WARNING: binding to {host} exposes the proxy and radar to your network.")
    web_server = WebRadarServer(host=host, port=web_port, storage=storage)
    proxy_service = ProxyService(host=host, port=proxy_port, storage=storage, upstream_url=upstream)

    try:
        web_server.start()
        proxy_service.start()
        print(f"[*] Web Radar UI:        http://{host}:{web_port}/")
        print(f"[*] Inline Proxy:        http://{host}:{proxy_port}/")
        print(f"[*] Intercepted Base:    http://{host}:{proxy_port}/v1")
        if upstream:
            print(f"[*] Target Upstream:     {upstream}")
        else:
            print(f"[*] Target Upstream:     None (Autonomous Zero-Cost Mock Echo)")
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
    prompt = args.prompt
    detector = ThreatDetector(block_threshold=args.threshold)
    redactor = Redactor()

    start = time.perf_counter()
    assessment = detector.evaluate(prompt)
    redaction = redactor.redact(prompt)
    duration_ms = (time.perf_counter() - start) * 1000

    print("=" * 60)
    print("  AGENT PROMPT FIREWALL • THREAT SCAN REPORT")
    print("=" * 60)
    print(f"Threat Score:          {assessment.score:.2f} / 1.00")
    print(f"Threat Classification: {assessment.threat_type}")
    print(f"Block Decision:        {'BLOCKED 🚫' if assessment.should_block else 'PERMITTED ✅'}")
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
    storage = FirewallStorage(db_path=args.db)
    stats = storage.get_stats()

    print("=" * 60)
    print("  AGENT PROMPT FIREWALL • TELEMETRY STATS")
    print("=" * 60)
    print(f"Total Prompts Scanned: {stats.get('total_scans', 0)}")
    print(f"Threats Blocked:       {stats.get('total_blocked', 0)}")
    print(f"Secrets/PII Redacted:  {stats.get('total_redactions', 0)}")
    print(f"Clean Traffic Rate:    {stats.get('clean_rate', 100.0)}%")
    print(f"Average Latency:       {stats.get('avg_latency_ms', 0.0)}ms")

    breakdown = stats.get("threat_breakdown", {})
    if breakdown:
        print("\nThreat Distribution:")
        for t_type, count in breakdown.items():
            print(f"  • {t_type.ljust(10)}: {count}")
    print("=" * 60)


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
        web_server = WebRadarServer(host="127.0.0.1", port=web_port, storage=storage)
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
    print("  AGENT PROMPT FIREWALL • RUN SESSION REPORT")
    print("=" * 60)
    print(f"  Session Duration:      {total_time}s")
    print(f"  Child Exit Code:       {exit_code}")
    print("=" * 60)
    sys.exit(exit_code)


def cmd_test(args: argparse.Namespace):
    """Run pytest test suite."""
    print("=" * 60)
    print("  AGENT PROMPT FIREWALL • RUNNING TEST SUITE")
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
        prog="agent-firewall",
        description="Autonomous Zero-Dependency Security Proxy & Threat Radar for AI Agents"
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # serve
    p_serve = subparsers.add_parser("serve", help="Launch Web Radar UI and Inline Proxy server")
    p_serve.add_argument("--web-port", type=int, default=8098, help="Web UI dashboard port (default: 8098)")
    p_serve.add_argument("--proxy-port", type=int, default=8099, help="Inline proxy port (default: 8099)")
    p_serve.add_argument("--db", default="firewall.db", help="SQLite database path")
    p_serve.add_argument("--upstream", default=None, help="Upstream LLM target URL (optional)")
    p_serve.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1; use 0.0.0.0 only on trusted networks)")
    p_serve.set_defaults(func=cmd_serve)

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan a prompt for injection attacks and sensitive data")
    p_scan.add_argument("prompt", help="Prompt text to analyze")
    p_scan.add_argument("--threshold", type=float, default=0.70, help="Threat blocking threshold (0.0 to 1.0)")
    p_scan.set_defaults(func=cmd_scan)

    # stats
    p_stats = subparsers.add_parser("stats", help="View aggregated firewall telemetry")
    p_stats.add_argument("--db", default="firewall.db", help="SQLite database path")
    p_stats.set_defaults(func=cmd_stats)

    # run
    p_run = subparsers.add_parser("run", help="Execute an agent command with transparent firewall interception")
    p_run.add_argument("--web-port", type=int, default=8098, help="Web UI dashboard port")
    p_run.add_argument("--proxy-port", type=int, default=8099, help="Inline proxy port")
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
    if hasattr(parsed, "cmd") and parsed.cmd and parsed.cmd[0] == "--":
        parsed.cmd = parsed.cmd[1:]

    parsed.func(parsed)


if __name__ == "__main__":
    main()
