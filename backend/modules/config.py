# -*- coding: utf-8 -*-
"""Konfiguracja aplikacji ładowana ze zmiennych środowiskowych."""

from dataclasses import dataclass
import os
from typing import Optional

from . import constants as C


def _env_bool(name: str, default: bool) -> bool:
    """Odczytuje zmienną środowiskową jako wartość logiczną.

    Akceptuje: ``1``, ``true``, ``yes``, ``y``, ``on`` (case-insensitive) → ``True``.
    Brak zmiennej lub nierozpoznana wartość zwraca ``default``.
    """
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "y", "on")


def _env_int(name: str, default: int) -> int:
    """Odczytuje zmienną środowiskową jako liczbę całkowitą.

    Brak zmiennej, pusta wartość lub nieparsowalna wartość zwraca ``default``.
    """
    val = os.environ.get(name)
    if val is None or not val.strip():
        return default
    try:
        return int(val.strip())
    except ValueError:
        return default


@dataclass(frozen=True)
class AppConfig:
    """Niemutowalna konfiguracja aplikacji.

    Wszystkie pola mają sensowne wartości domyślne zdefiniowane w ``constants``.
    Instancję należy tworzyć przez :meth:`from_env`, które odczytuje zmienne
    środowiskowe i uruchamia walidację.

    Attributes:
        listen:               Adres IP, na którym nasłuchuje serwer HTTP.
        port:                 Port serwera HTTP (1–65535).
        max_body_bytes:       Maksymalny rozmiar body żądania POST w bajtach.
        nvd_api_key:          Klucz API do NVD (opcjonalny; bez klucza limit ~5 req/30s).
        cve_api_token:        Token wymagany w nagłówku ``X-API-Token`` (opcjonalny).
        log_level:            Poziom logowania (DEBUG/INFO/WARNING/ERROR).
        log_json:             Czy logować w formacie JSON (dla agregatorów logów).
        log_request_id:       Czy dołączać ``request_id`` do każdego wpisu logu.
        cache_enabled:        Czy włączyć plikowy cache odpowiedzi NVD.
        cache_path:           Ścieżka do pliku JSON cache NVD.
        cache_ttl_seconds:    Czas życia wpisu cache w sekundach (0 = brak wygaśnięcia).
        http_timeout_seconds: Timeout żądań HTTP do NVD API w sekundach.
        nvd_base_url:         Bazowy URL NVD API (można nadpisać dla testów/mirror).
    """

    # Serwer
    listen: str = C.DEFAULT_LISTEN
    port: int = C.DEFAULT_PORT
    max_body_bytes: int = C.DEFAULT_MAX_BODY_BYTES

    # Klucze / autoryzacja
    nvd_api_key: Optional[str] = None
    cve_api_token: Optional[str] = None

    # Logowanie
    log_level: str = C.DEFAULT_LOG_LEVEL
    log_json: bool = C.DEFAULT_LOG_JSON
    log_request_id: bool = C.DEFAULT_LOG_REQUEST_ID

    # Cache NVD
    cache_enabled: bool = C.DEFAULT_CACHE_ENABLED
    cache_path: str = C.DEFAULT_CACHE_FILENAME
    cache_ttl_seconds: int = C.DEFAULT_CACHE_TTL_SECONDS

    # HTTP / NVD
    http_timeout_seconds: int = C.DEFAULT_HTTP_TIMEOUT_SECONDS
    nvd_base_url: str = C.NVD_BASE_URL

    @staticmethod
    def from_env(
        *,
        listen: Optional[str] = None,
        port: Optional[int] = None,
    ) -> "AppConfig":
        """Tworzy ``AppConfig`` ze zmiennych środowiskowych.

        Parametry ``listen`` i ``port`` (przekazane przez CLI) mają wyższy
        priorytet niż odpowiadające im zmienne środowiskowe.

        Args:
            listen: Nadpisanie adresu nasłuchu (z argumentu ``--listen``).
            port:   Nadpisanie portu (z argumentu ``--port``).

        Returns:
            Zwalidowana, niemutowalna instancja ``AppConfig``.

        Raises:
            ValueError: Jeśli którakolwiek wartość konfiguracji jest nieprawidłowa.
        """
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
        """Sprawdza spójność konfiguracji.

        Raises:
            ValueError: Jeśli którakolwiek wartość jest poza dopuszczalnym zakresem.
        """
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
