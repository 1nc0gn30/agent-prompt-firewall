"""
services.py - Root entrypoint for Agent Prompt Firewall services and SSE telemetry.
Provides live streaming endpoint at GET /api/events/stream and inline proxy on port 8198.
Zero external dependencies (Python 3.10+ standard library).
Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
"""

import sys
from pathlib import Path

src_dir = Path(__file__).resolve().parent / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from agent_prompt_firewall.services import (
    WebRadarServer,
    FirewallRequestHandler,
    ThreadedWebServer,
    ProxyService,
    ProxyRequestHandler,
    ThreadedProxyServer,
    FirewallStorage,
    GLOBAL_BROADCASTER,
    EventBroadcaster,
    FirewallServicesManager,
    start_services,
    stop_services,
)

__all__ = [
    "WebRadarServer",
    "FirewallRequestHandler",
    "ThreadedWebServer",
    "ProxyService",
    "ProxyRequestHandler",
    "ThreadedProxyServer",
    "FirewallStorage",
    "GLOBAL_BROADCASTER",
    "EventBroadcaster",
    "FirewallServicesManager",
    "start_services",
    "stop_services",
]

if __name__ == "__main__":
    from agent_prompt_firewall.cli import main
    main()
