"""
storage.py - Thread-safe SQLite Telemetry and Threat Log Storage.
Zero external dependencies (Python 3.10+ standard library).
"""

import json
import queue
import sqlite3
import threading
import time
from typing import Dict, Any, List, Optional


class EventBroadcaster:
    """Thread-safe event fan-out broadcaster for SSE streams."""
    def __init__(self):
        self._subscribers: List[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=100)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue):
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def broadcast(self, event_type: str, data: Dict[str, Any]):
        msg = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
        with self._lock:
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(msg)
                except queue.Full:
                    dead.append(q)
            for d in dead:
                if d in self._subscribers:
                    self._subscribers.remove(d)


GLOBAL_BROADCASTER = EventBroadcaster()



class FirewallStorage:
    def __init__(self, db_path: str = "firewall.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        direction TEXT NOT NULL,
                        prompt_snippet TEXT,
                        threat_score REAL NOT NULL,
                        threat_type TEXT NOT NULL,
                        categories TEXT,
                        details TEXT,
                        blocked INTEGER NOT NULL,
                        redacted_count INTEGER NOT NULL,
                        redactions_json TEXT,
                        duration_ms REAL,
                        source_ip TEXT
                    )
                """)
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS threat_events (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        threat_type TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        payload_preview TEXT
                    )
                """)
                cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
                cur.execute("CREATE INDEX IF NOT EXISTS idx_scans_threat_type ON scans(threat_type)")
                conn.commit()
            finally:
                conn.close()

    def log_scan(self, scan_data: Dict[str, Any]) -> int:
        timestamp = scan_data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")
        direction = scan_data.get("direction", "inbound")
        prompt_snippet = (scan_data.get("prompt_snippet") or "")[:200]
        threat_score = float(scan_data.get("threat_score", 0.0))
        threat_type = scan_data.get("threat_type", "CLEAN")
        categories_json = json.dumps(scan_data.get("categories", []))
        details_json = json.dumps(scan_data.get("details", []))
        blocked = 1 if scan_data.get("blocked", False) else 0
        redacted_count = int(scan_data.get("redacted_count", 0))
        redactions_json = json.dumps(scan_data.get("findings", []))
        duration_ms = float(scan_data.get("duration_ms", 0.0))
        source_ip = scan_data.get("source_ip", "127.0.0.1")

        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO scans (
                        timestamp, direction, prompt_snippet, threat_score, threat_type,
                        categories, details, blocked, redacted_count, redactions_json,
                        duration_ms, source_ip
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, direction, prompt_snippet, threat_score, threat_type,
                    categories_json, details_json, blocked, redacted_count, redactions_json,
                    duration_ms, source_ip
                ))
                scan_id = cur.lastrowid

                if blocked or threat_type in ("CRITICAL", "HIGH"):
                    reason = ", ".join(scan_data.get("details", [])) or threat_type
                    cur.execute("""
                        INSERT INTO threat_events (timestamp, threat_type, reason, payload_preview)
                        VALUES (?, ?, ?, ?)
                    """, (timestamp, threat_type, reason[:255], prompt_snippet[:150]))

                conn.commit()
                return scan_id or 0
            finally:
                conn.close()

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*), SUM(blocked), SUM(redacted_count), AVG(duration_ms) FROM scans")
                row = cur.fetchone()
                total_scans = row[0] or 0
                total_blocked = row[1] or 0
                total_redacted = row[2] or 0
                avg_latency = round(row[3] or 0.0, 2)

                # Threat distribution
                cur.execute("SELECT threat_type, COUNT(*) FROM scans GROUP BY threat_type")
                breakdown = {r[0]: r[1] for r in cur.fetchall()}

                # Direction counts
                cur.execute("SELECT direction, COUNT(*) FROM scans GROUP BY direction")
                directions = {r[0]: r[1] for r in cur.fetchall()}

                return {
                    "total_scans": total_scans,
                    "total_blocked": total_blocked,
                    "total_redactions": total_redacted,
                    "avg_latency_ms": avg_latency,
                    "threat_breakdown": breakdown,
                    "direction_breakdown": directions,
                    "clean_rate": round(((total_scans - total_blocked) / total_scans * 100), 1) if total_scans > 0 else 100.0
                }
            finally:
                conn.close()

    def get_recent_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                cur.execute("""
                    SELECT id, timestamp, threat_type, reason, payload_preview
                    FROM threat_events
                    ORDER BY id DESC LIMIT ?
                """, (limit,))
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                cur.execute("""
                    SELECT id, timestamp, direction, prompt_snippet, threat_score,
                           threat_type, categories, details, blocked, redacted_count,
                           duration_ms, source_ip
                    FROM scans
                    ORDER BY id DESC LIMIT ?
                """, (limit,))
                results = []
                for row in cur.fetchall():
                    item = dict(row)
                    item["categories"] = json.loads(item["categories"] or "[]")
                    item["details"] = json.loads(item["details"] or "[]")
                    item["blocked"] = bool(item["blocked"])
                    results.append(item)
                return results
            finally:
                conn.close()

    def clear(self):
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                cur.execute("DELETE FROM scans")
                cur.execute("DELETE FROM threat_events")
                conn.commit()
            finally:
                conn.close()
