# -*- coding: utf-8 -*-
"""Plikowy cache TTL oparty na JSON, bezpieczny wątkowo."""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, Optional

from .errors import CacheError


class FileTTLCache:
    """Plikowy cache z wygasaniem wpisów (TTL), przechowujący dane w JSON.

    Struktura pliku cache::

        {
          "CVE-2024-1234": {"expires_at": 1730000000, "value": {...}},
          ...
        }

    ``expires_at`` to timestamp UNIX (int).  Wartość ``0`` oznacza brak wygaśnięcia.

    Operacje ``get`` i ``set`` są chronione ``threading.RLock``, więc instancja
    jest bezpieczna przy współbieżnym dostępie z wielu wątków (np. ThreadingHTTPServer).

    Plik jest ładowany leniwie (lazy-load) przy pierwszym dostępie, co pozwala
    tworzyć instancję przed sprawdzeniem uprawnień do pliku.

    Attributes:
        path:        Ścieżka do pliku JSON cache.
        ttl_seconds: Domyślny czas życia wpisu w sekundach (0 = bez wygaśnięcia).
        enabled:     Czy cache jest aktywny.  ``False`` sprawia, że wszystkie
                     operacje są no-op (``get`` zwraca ``None``, ``set`` ignorowany).
    """

    def __init__(self, path: str, ttl_seconds: int, enabled: bool = True) -> None:
        self.path = path
        self.ttl_seconds = int(ttl_seconds)
        self.enabled = enabled
        self._lock = threading.RLock()
        self._data: Dict[str, Dict[str, Any]] = {}
        self._loaded = False

    def _now(self) -> int:
        """Zwraca bieżący czas jako timestamp UNIX (int)."""
        return int(time.time())

    def _load_if_needed(self) -> None:
        """Wczytuje plik cache przy pierwszym dostępie (double-checked locking).

        Raises:
            CacheError: Jeśli plik istnieje, ale nie można go odczytać lub sparsować.
        """
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
        """Zapisuje stan cache do pliku atomowo (zapis do .tmp + rename).

        Raises:
            CacheError: Jeśli zapis lub rename się nie powiodły.
        """
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
        """Usuwa z pamięci i z pliku wszystkie wygasłe wpisy."""
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
        """Zwraca wartość dla klucza lub ``None``, jeśli wpis nie istnieje / wygasł.

        Wygasłe wpisy są usuwane z pamięci i pliku przy okazji odczytu.

        Args:
            key: Klucz wpisu (np. identyfikator CVE).

        Returns:
            Przechowana wartość lub ``None``.
        """
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
        """Zapisuje wartość pod kluczem z opcjonalnym własnym TTL.

        Args:
            key:         Klucz wpisu.
            value:       Wartość do przechowania (musi być serializowalna do JSON).
            ttl_seconds: Czas życia wpisu w sekundach.  ``None`` używa domyślnego TTL
                         instancji.  ``0`` oznacza brak wygaśnięcia.

        Raises:
            CacheError: Jeśli zapis do pliku się nie powiódł.
        """
        self._load_if_needed()
        if not self.enabled:
            return
        ttl = self.ttl_seconds if ttl_seconds is None else int(ttl_seconds)
        exp = (self._now() + ttl) if ttl > 0 else 0
        with self._lock:
            self._data[key] = {"expires_at": exp, "value": value}
            self._save()
