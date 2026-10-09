"""
server.py - Compatibility wrapper re-exporting WebRadarServer and FirewallRequestHandler.
"""

from .web_radar import (
    WebRadarServer,
    FirewallRequestHandler,
    ThreadedWebServer,
)

__all__ = [
    "WebRadarServer",
    "FirewallRequestHandler",
    "ThreadedWebServer",
]
