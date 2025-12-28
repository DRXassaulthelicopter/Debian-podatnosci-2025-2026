# -*- coding: utf-8 -*-
from dataclasses import dataclass
import os
from typing import Optional

from . import constants as C


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    val = val.strip().lower()
    return val in ("1", "true", "yes", "y", "on")


def _env_int(name: str, default: int) -> int:
    val = os.environ.get(name)
    if val is None or not val.strip():
        return default
    try:
        return int(val.strip())
    except ValueError:
        return default


@dataclass(frozen=True)
class AppConfig:
    # Server
    listen: str = C.DEFAULT_LISTEN
    port: int = C.DEFAULT_PORT
    max_body_bytes: int = C.DEFAULT_MAX_BODY_BYTES

    # Auth / keys
    nvd_api_key: Optional[str] = None
    cve_api_token: Optional[str] = None

    # Logging
    log_level: str = C.DEFAULT_LOG_LEVEL
    log_json: bool = C.DEFAULT_LOG_JSON
    log_request_id: bool = C.DEFAULT_LOG_REQUEST_ID

    # Cache
    cache_enabled: bool = C.DEFAULT_CACHE_ENABLED
    cache_path: str = C.DEFAULT_CACHE_FILENAME
    cache_ttl_seconds: int = C.DEFAULT_CACHE_TTL_SECONDS

    # HTTP / NVD
    http_timeout_seconds: int = C.DEFAULT_HTTP_TIMEOUT_SECONDS
    nvd_base_url: str = C.NVD_BASE_URL

    @staticmethod
    def from_env(*, listen: Optional[str] = None, port: Optional[int] = None) -> "AppConfig":
        env_listen = listen or os.environ.get(C.ENV_LISTEN) or C.DEFAULT_LISTEN
        env_port = port if port is not None else _env_int(C.ENV_PORT, C.DEFAULT_PORT)

        cfg = AppConfig(
            listen=env_listen,
            port=env_port,
            max_body_bytes=_env_int(C.ENV_MAX_BODY, C.DEFAULT_MAX_BODY_BYTES),

            nvd_api_key=os.environ.get(C.ENV_NVD_API_KEY),
            cve_api_token=os.environ.get(C.ENV_CVE_API_TOKEN),

            log_level=(os.environ.get(C.ENV_LOG_LEVEL) or C.DEFAULT_LOG_LEVEL).upper(),
            log_json=_env_bool(C.ENV_LOG_JSON, C.DEFAULT_LOG_JSON),
            log_request_id=_env_bool(C.ENV_LOG_REQUEST_ID, C.DEFAULT_LOG_REQUEST_ID),

            cache_enabled=_env_bool(C.ENV_CACHE_ENABLED, C.DEFAULT_CACHE_ENABLED),
            cache_path=os.environ.get(C.ENV_CACHE_PATH) or C.DEFAULT_CACHE_FILENAME,
            cache_ttl_seconds=_env_int(C.ENV_CACHE_TTL, C.DEFAULT_CACHE_TTL_SECONDS),

            http_timeout_seconds=_env_int(C.ENV_HTTP_TIMEOUT, C.DEFAULT_HTTP_TIMEOUT_SECONDS),
            nvd_base_url=os.environ.get(C.ENV_NVD_BASE_URL) or C.NVD_BASE_URL,
        )
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not self.listen:
            raise ValueError("listen nie może być puste")
        if not (1 <= int(self.port) <= 65535):
            raise ValueError("port musi być w zakresie 1..65535")
        if self.max_body_bytes <= 0:
            raise ValueError("max_body_bytes musi być > 0")
        if self.cache_ttl_seconds < 0:
            raise ValueError("cache_ttl_seconds nie może być ujemny")
        if self.http_timeout_seconds <= 0:
            raise ValueError("http_timeout_seconds musi być > 0")
        if not self.nvd_base_url:
            raise ValueError("nvd_base_url nie może być puste")
