import hashlib
import json
import os
import sqlite3
import time
from dataclasses import dataclass
from typing import Any, Optional

from config import get_cache_path, get_cache_ttl_days


@dataclass
class CacheEntry:
    key: str
    payload: Any
    created_at: float


class SoloditCache:
    def __init__(self, path: Optional[str] = None, ttl_days: Optional[int] = None) -> None:
        self.path = path or get_cache_path()
        self.ttl_seconds = (ttl_days or get_cache_ttl_days()) * 24 * 60 * 60
        self._ensure_dir()
        self._init_db()

    def _ensure_dir(self) -> None:
        dir_path = os.path.dirname(self.path)
        if dir_path and not os.path.exists(dir_path):
            os.makedirs(dir_path, exist_ok=True)

    def _init_db(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    payload TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )

    @staticmethod
    def make_key(method: str, url: str, params: Optional[dict], body: Optional[dict]) -> str:
        canonical = json.dumps(
            {
                "method": method.upper(),
                "url": url,
                "params": params or {},
                "body": body or {},
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def get(self, key: str) -> Optional[CacheEntry]:
        now = time.time()
        with sqlite3.connect(self.path) as conn:
            row = conn.execute(
                "SELECT payload, created_at FROM cache WHERE key = ?", (key,)
            ).fetchone()
        if not row:
            return None
        payload_text, created_at = row
        if now - created_at > self.ttl_seconds:
            self.delete(key)
            return None
        try:
            payload = json.loads(payload_text)
        except json.JSONDecodeError:
            return None
        return CacheEntry(key=key, payload=payload, created_at=created_at)

    def set(self, key: str, payload: Any) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cache (key, payload, created_at) VALUES (?, ?, ?)",
                (key, json.dumps(payload), time.time()),
            )

    def delete(self, key: str) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("DELETE FROM cache WHERE key = ?", (key,))

    def clear(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute("DELETE FROM cache")
