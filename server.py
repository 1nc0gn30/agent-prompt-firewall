#!/usr/bin/env python3
"""
server.py: Production HTTP Daemon for Agent Prompt Firewall.
Orchestrates Web Radar UI (port 8098) with SSE stream (/api/events/stream)
and Inline Interception Proxy (port 8198).
Zero external pip dependencies.
"""

import argparse
import os
import signal
import sys
import time

# Ensure src/ is in sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(BASE_DIR, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from agent_prompt_firewall.services import FirewallServicesManager


def main():
    parser = argparse.ArgumentParser(description="Agent Prompt Firewall Sovereign Daemon")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--web-port", "--port", dest="web_port", type=int, default=8098, help="Web Radar UI port (default: 8098)")
    parser.add_argument("--proxy-port", type=int, default=8198, help="Inline Interception Proxy port (default: 8198)")
    parser.add_argument("--db", default=os.path.join(BASE_DIR, "firewall.db"), help="Path to SQLite database")
    parser.add_argument("--upstream", default=None, help="Optional upstream LLM base URL for proxy forwarding")
    args = parser.parse_args()

    manager = FirewallServicesManager(
        web_host=args.host,
        web_port=args.web_port,
        proxy_host=args.host,
        proxy_port=args.proxy_port,
        db_path=args.db,
        upstream_url=args.upstream
    )

    def handle_signal(sig, frame):
        print("\nShutting down Agent Prompt Firewall gracefully...")
        manager.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    manager.start()

    print(f"✦ Agent Prompt Firewall running:")
    print(f"  Web Radar Dashboard : http://{args.host}:{args.web_port}/")
    print(f"  Health Check        : http://{args.host}:{args.web_port}/health")
    print(f"  Live SSE Stream     : http://{args.host}:{args.web_port}/api/events/stream")
    print(f"  Inline Proxy        : http://{args.host}:{args.proxy_port}/")
    print(f"  Database Storage    : {args.db}")
    print("  Access              : 100% Free & Open Access (Zero Paywalls)")

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        handle_signal(None, None)


if __name__ == "__main__":
    main()
