"""
services.py - Unified Service Coordinator for Agent Prompt Firewall.
Orchestrates Web Radar UI (port 8098) with SSE stream (/api/events/stream)
and Inline Interception Proxy (port 8099).
Zero external dependencies (Python 3.10+ standard library).
"""

import time
from typing import Optional

from .storage import FirewallStorage, GLOBAL_BROADCASTER, EventBroadcaster
from .web_radar import WebRadarServer, FirewallRequestHandler, ThreadedWebServer
from .proxy import ProxyService, ProxyRequestHandler, ThreadedProxyServer


class FirewallServicesManager:
    """Manages both the Web Radar Dashboard (SSE /api/events/stream) and Inline Security Proxy."""

    def __init__(
        self,
        web_host: str = "127.0.0.1",
        web_port: int = 8098,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 8099,
        db_path: str = "firewall.db",
        upstream_url: Optional[str] = None,
        block_threshold: float = 0.70
    ):
        self.web_host = web_host
        self.web_port = web_port
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.storage = FirewallStorage(db_path=db_path)
        self.upstream_url = upstream_url
        self.block_threshold = block_threshold

        self.web_server = WebRadarServer(
            host=self.web_host,
            port=self.web_port,
            storage=self.storage
        )
        self.proxy_service = ProxyService(
            host=self.proxy_host,
            port=self.proxy_port,
            storage=self.storage,
            upstream_url=self.upstream_url
        )

    def start(self):
        """Start both services."""
        self.web_server.start()
        self.proxy_service.start()
        time.sleep(0.1)

    def stop(self):
        """Stop both services."""
        self.web_server.stop()
        self.proxy_service.stop()

    @property
    def broadcaster(self) -> EventBroadcaster:
        return GLOBAL_BROADCASTER


def start_services(
    web_port: int = 8098,
    proxy_port: int = 8099,
    db_path: str = "firewall.db",
    upstream: Optional[str] = None
) -> FirewallServicesManager:
    """Convenience helper to spin up all firewall services with SSE endpoint /api/events/stream."""
    manager = FirewallServicesManager(
        web_port=web_port,
        proxy_port=proxy_port,
        db_path=db_path,
        upstream_url=upstream
    )
    manager.start()
    return manager


def stop_services(manager: FirewallServicesManager):
    """Convenience helper to shut down firewall services."""
    if manager:
        manager.stop()


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
