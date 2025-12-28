# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import logging
import sys
import time
from contextvars import ContextVar
from typing import Optional

from .config import AppConfig

_request_id: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


def set_request_id(rid: Optional[str]) -> None:
    _request_id.set(rid)


def get_request_id() -> Optional[str]:
    return _request_id.get()


class RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = get_request_id()
        return True


class JsonFormatter(logging.Formatter):
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

    # umiarkowane wyciszenie urllib3
    logging.getLogger("urllib3").setLevel(max(level, logging.WARNING))


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
