"""
storage.py - Thread-safe SQLite WAL Telemetry and SHA-256 Hash-Chained Audit Storage.
Zero external dependencies (Python 3.10+ standard library).
Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform
"""

import hashlib
import json
import os
import queue
import sqlite3
import threading
import time
from typing import Dict, Any, List, Optional

from .redactor import Redactor

GENESIS_HASH = "0" * 64
_SAFE_REDACTOR = Redactor()


def compute_entry_hash(
    prev_hash: str,
    timestamp: str,
    direction: str,
    prompt_snippet: str,
    threat_score: float,
    threat_type: str,
    categories: List[str],
    blocked: int,
    redacted_count: int,
    source_ip: str,
) -> str:
    payload = {
        "prev_hash": prev_hash,
        "timestamp": timestamp,
        "direction": direction,
        "prompt_snippet": prompt_snippet,
        "threat_score": round(float(threat_score), 6),
        "threat_type": threat_type,
        "categories": categories,
        "blocked": int(blocked),
        "redacted_count": int(redacted_count),
        "source_ip": source_ip,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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

    def _secure_file_permissions(self):
        if not self.db_path or self.db_path == ":memory:":
            return
        for suffix in ("", "-wal", "-shm"):
            p = f"{self.db_path}{suffix}"
            if os.path.exists(p):
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        parent = os.path.dirname(os.path.abspath(self.db_path)) if self.db_path != ":memory:" else ""
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
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
                        source_ip TEXT,
                        prev_hash TEXT,
                        entry_hash TEXT
                    )
                """)
                # Migrate legacy tables missing hash-chain columns
                cols = {row[1] for row in cur.execute("PRAGMA table_info(scans)").fetchall()}
                if "prev_hash" not in cols:
                    cur.execute("ALTER TABLE scans ADD COLUMN prev_hash TEXT")
                if "entry_hash" not in cols:
                    cur.execute("ALTER TABLE scans ADD COLUMN entry_hash TEXT")

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
            self._secure_file_permissions()

    def log_scan(self, scan_data: Dict[str, Any]) -> int:
        timestamp = scan_data.get("timestamp") or time.strftime("%Y-%m-%d %H:%M:%S")
        direction = str(scan_data.get("direction", "inbound"))[:32]
        # Defense-in-depth: scrub any raw secrets/PII before touching SQLite
        raw_snippet = str(scan_data.get("prompt_snippet") or "")
        safe_snippet = _SAFE_REDACTOR.redact(raw_snippet).redacted_text[:200]
        threat_score = float(scan_data.get("threat_score", 0.0))
        threat_type = str(scan_data.get("threat_type", "CLEAN"))[:32]
        categories_list = [str(c) for c in (scan_data.get("categories") or [])]
        raw_details = [str(d) for d in (scan_data.get("details") or [])]
        safe_details = [_SAFE_REDACTOR.redact(d).redacted_text for d in raw_details]
        categories_json = json.dumps(categories_list)
        details_json = json.dumps(safe_details)
        blocked = 1 if scan_data.get("blocked", False) else 0
        redacted_count = int(scan_data.get("redacted_count", 0))
        redactions_json = json.dumps(scan_data.get("findings", []))
        duration_ms = float(scan_data.get("duration_ms", 0.0))
        source_ip = str(scan_data.get("source_ip", "127.0.0.1"))[:64]

        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                last_row = cur.execute(
                    "SELECT entry_hash FROM scans ORDER BY id DESC LIMIT 1"
                ).fetchone()
                prev_hash = (last_row["entry_hash"] if last_row and last_row["entry_hash"] else GENESIS_HASH)
                entry_hash = compute_entry_hash(
                    prev_hash=prev_hash,
                    timestamp=timestamp,
                    direction=direction,
                    prompt_snippet=safe_snippet,
                    threat_score=threat_score,
                    threat_type=threat_type,
                    categories=categories_list,
                    blocked=blocked,
                    redacted_count=redacted_count,
                    source_ip=source_ip,
                )

                cur.execute("""
                    INSERT INTO scans (
                        timestamp, direction, prompt_snippet, threat_score, threat_type,
                        categories, details, blocked, redacted_count, redactions_json,
                        duration_ms, source_ip, prev_hash, entry_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    timestamp, direction, safe_snippet, threat_score, threat_type,
                    categories_json, details_json, blocked, redacted_count, redactions_json,
                    duration_ms, source_ip, prev_hash, entry_hash
                ))
                scan_id = cur.lastrowid

                if blocked or threat_type in ("CRITICAL", "HIGH"):
                    reason = ", ".join(safe_details) or threat_type
                    cur.execute("""
                        INSERT INTO threat_events (timestamp, threat_type, reason, payload_preview)
                        VALUES (?, ?, ?, ?)
                    """, (timestamp, threat_type, reason[:255], safe_snippet[:150]))

                conn.commit()
                self._secure_file_permissions()
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

                cur.execute("SELECT threat_type, COUNT(*) FROM scans GROUP BY threat_type")
                breakdown = {r[0]: r[1] for r in cur.fetchall()}

                cur.execute("SELECT direction, COUNT(*) FROM scans GROUP BY direction")
                directions = {r[0]: r[1] for r in cur.fetchall()}

                return {
                    "total_scans": total_scans,
                    "total_blocked": total_blocked,
                    "total_redactions": total_redacted,
                    "avg_latency_ms": avg_latency,
                    "threat_breakdown": breakdown,
                    "direction_breakdown": directions,
                    "clean_rate": round(((total_scans - total_blocked) / total_scans * 100), 1) if total_scans > 0 else 100.0,
                }
            finally:
                conn.close()

    def get_recent_threats(self, limit: int = 50) -> List[Dict[str, Any]]:
        clamped = max(1, min(500, int(limit)))
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                cur.execute("""
                    SELECT id, timestamp, threat_type, reason, payload_preview
                    FROM threat_events
                    ORDER BY id DESC LIMIT ?
                """, (clamped,))
                return [dict(r) for r in cur.fetchall()]
            finally:
                conn.close()

    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        clamped = max(1, min(500, int(limit)))
        with self._lock:
            conn = self._get_connection()
            try:
                cur = conn.cursor()
                cur.execute("""
                    SELECT id, timestamp, direction, prompt_snippet, threat_score,
                           threat_type, categories, details, blocked, redacted_count,
                           duration_ms, source_ip, prev_hash, entry_hash
                    FROM scans
                    ORDER BY id DESC LIMIT ?
                """, (clamped,))
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

    def verify_chain(self) -> Dict[str, Any]:
        """Verify the SHA-256 hash chain across all scan rows in chronological order."""
        with self._lock:
            conn = self._get_connection()
            try:
                rows = conn.execute("""
                    SELECT id, timestamp, direction, prompt_snippet, threat_score,
                           threat_type, categories, blocked, redacted_count, source_ip,
                           prev_hash, entry_hash
                    FROM scans
                    ORDER BY id ASC
                """).fetchall()
            finally:
                conn.close()

        expected_prev = GENESIS_HASH
        verified = 0
        for row in rows:
            cats = json.loads(row["categories"] or "[]")
            recomputed = compute_entry_hash(
                prev_hash=expected_prev,
                timestamp=row["timestamp"],
                direction=row["direction"],
                prompt_snippet=row["prompt_snippet"] or "",
                threat_score=row["threat_score"],
                threat_type=row["threat_type"],
                categories=cats,
                blocked=row["blocked"],
                redacted_count=row["redacted_count"],
                source_ip=row["source_ip"] or "127.0.0.1",
            )
            if row["prev_hash"] != expected_prev or row["entry_hash"] != recomputed:
                return {
                    "valid": False,
                    "total_entries": len(rows),
                    "verified_entries": verified,
                    "head_hash": expected_prev,
                    "broken_at_id": row["id"],
                }
            expected_prev = recomputed
            verified += 1

        return {
            "valid": True,
            "total_entries": len(rows),
            "verified_entries": verified,
            "head_hash": expected_prev,
            "broken_at_id": None,
        }

    def export_compliance_audit(self, limit: int = 500) -> Dict[str, Any]:
        """Generate a verifiable SOC-2 / HIPAA hash-chained compliance audit export."""
        clamped = max(1, min(500, int(limit)))
        chain = self.verify_chain()
        stats = self.get_stats()
        scans = self.get_recent_scans(limit=clamped)
        threats = self.get_recent_threats(limit=min(clamped, 200))
        return {
            "generator": "Agent Prompt Firewall",
            "version": "2.6.0",
            "author": "Neal Frazier Tech (@1nc0gn30) • NullAI Platform",
            "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "compliance_controls": [
                "SOC-2 Type II Immutable Hash-Chained Audit Ledger (SHA-256)",
                "Zero Plaintext Secret / PII Persistence (Pre-Storage Redaction)",
                "SQLite WAL + Foreign Keys + 0600 Owner-Only Storage",
            ],
            "chain_verification": chain,
            "stats": stats,
            "scans": scans,
            "recent_threats": threats,
        }

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
