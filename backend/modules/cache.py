# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, Optional

from .errors import CacheError


class FileTTLCache:
    """
    Plikowy cache TTL (JSON):
    {
      "CVE-xxxx-xxxx": {"expires_at": 1730000000, "value": {...}},
      ...
    }
    """
    def __init__(self, path: str, ttl_seconds: int, enabled: bool = True):
        self.path = path
        self.ttl_seconds = int(ttl_seconds)
        self.enabled = enabled
        self._lock = threading.RLock()
        self._data: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    def _now(self) -> int:
        return int(time.time())

    def _load_if_needed(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            if not self.enabled:
                self._data = {}
                self._loaded = True
                return
            if not os.path.exists(self.path):
                self._data = {}
                self._loaded = True
                return
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                if not isinstance(raw, dict):
                    raise CacheError("Cache file is not a dict")
                self._data = raw
                self._loaded = True
                self.prune()
            except Exception as e:
                raise CacheError(f"Nie udało się wczytać cache: {e}", cause=e)

    def _save(self) -> None:
        if not self.enabled:
            return
        tmp = f"{self.path}.tmp"
        try:
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.path)
        except Exception as e:
            raise CacheError(f"Nie udało się zapisać cache: {e}", cause=e)

    def prune(self) -> None:
        self._load_if_needed()
        if not self.enabled:
            return
        now = self._now()
        with self._lock:
            changed = False
            for k in list(self._data.keys()):
                try:
                    exp = int(self._data[k].get("expires_at", 0) or 0)
                except Exception:
                    exp = 0
                if exp and exp <= now:
                    self._data.pop(k, None)
                    changed = True
            if changed:
                self._save()

    def get(self, key: str) -> Optional[Any]:
        self._load_if_needed()
        if not self.enabled:
            return None
        now = self._now()
        with self._lock:
            entry = self._data.get(key)
            if not entry:
                return None
            exp = int(entry.get("expires_at", 0) or 0)
            if exp and exp <= now:
                self._data.pop(key, None)
                try:
                    self._save()
                except Exception:
                    pass
                return None
            return entry.get("value")

    def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        self._load_if_needed()
        if not self.enabled:
            return
        ttl = self.ttl_seconds if ttl_seconds is None else int(ttl_seconds)
        exp = (self._now() + ttl) if ttl > 0 else 0
        with self._lock:
            self._data[key] = {"expires_at": exp, "value": value}
            self._save()
