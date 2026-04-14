# -*- coding: utf-8 -*-
"""Konfiguracja logowania: formatery (JSON / tekst) i propagacja request-id przez wątki."""

from __future__ import annotations

import json
import logging
import sys
import time
from contextvars import ContextVar
from typing import Optional

from .config import AppConfig

# ContextVar przechowuje request-id niezależnie dla każdego wątku/coroutine.
_request_id: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


def set_request_id(rid: Optional[str]) -> None:
    """Ustawia request-id dla bieżącego kontekstu (wątku)."""
    _request_id.set(rid)


def get_request_id() -> Optional[str]:
    """Zwraca request-id bieżącego kontekstu lub ``None``."""
    return _request_id.get()


class RequestIdFilter(logging.Filter):
    """Filtr logowania dołączający atrybut ``request_id`` do każdego rekordu."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()  # type: ignore[attr-defined]
        return True


class JsonFormatter(logging.Formatter):
    """Formatuje rekord logu jako pojedynczą linię JSON.

    Przykład wyjścia::

        {"ts": 1700000000, "level": "INFO", "logger": "modules.api_server",
         "msg": "Listening on http://127.0.0.1:8088", "request_id": "abc-123"}
    """

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": int(time.time()),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        rid = getattr(record, "request_id", None)
        if rid:
            payload["request_id"] = rid
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def setup_logging(cfg: AppConfig) -> None:
    """Konfiguruje root logger na podstawie ``AppConfig``.

    Usuwa istniejące handlery i zastępuje je jednym ``StreamHandler`` (stdout).
    Wybiera formater JSON lub tekstowy w zależności od ``cfg.log_json``.
    Wycisza bibliotekę ``urllib3`` do poziomu WARNING, by nie zaśmiecać logów.

    Args:
        cfg: Konfiguracja aplikacji z parametrami logowania.
    """
    level = getattr(logging, (cfg.log_level or "INFO").upper(), logging.INFO)

    root = logging.getLogger()
    root.setLevel(level)
    while root.handlers:
        root.handlers.pop()

    h = logging.StreamHandler(sys.stdout)
    h.setLevel(level)

    if cfg.log_json:
        h.setFormatter(JsonFormatter())
    else:
        fmt = "%(asctime)s %(levelname)s %(name)s"
        if cfg.log_request_id:
            fmt += " [rid=%(request_id)s]"
        fmt += " - %(message)s"
        h.setFormatter(logging.Formatter(fmt))

    if cfg.log_request_id:
        h.addFilter(RequestIdFilter())

    root.addHandler(h)

    # Wyciszenie urllib3 — jego DEBUG/INFO byłoby zbyt gadatliwe przy skanowaniu.
    logging.getLogger("urllib3").setLevel(max(level, logging.WARNING))


def get_logger(name: str) -> logging.Logger:
    """Zwraca nazwany logger (cienki wrapper nad ``logging.getLogger``)."""
    return logging.getLogger(name)
