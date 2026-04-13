#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE Scan API — punkt wejścia aplikacji.

Parsuje argumenty CLI, buduje konfigurację ze zmiennych środowiskowych,
inicjalizuje komponenty (cache, serwis skanowania, serwer HTTP) i uruchamia
serwer.

Użycie::

    python3 main.py [--listen <ip>] [--port <port>]

Zmienne środowiskowe (patrz ``modules/constants.py`` i ``dotfiles/scanner.env``):
    NVD_API_KEY      — klucz API NVD (opcjonalny, bez klucza limit 5 req/30 s)
    CVE_API_TOKEN    — token uwierzytelniający HTTP (opcjonalny, ale zalecany)
    CVE_PORT         — port nasłuchu (domyślnie 8088)
    CVE_LISTEN       — adres nasłuchu (domyślnie 127.0.0.1)
    CVE_CACHE_*      — ustawienia cache NVD
    CVE_LOG_*        — ustawienia logowania
"""

import argparse
import os

from modules.cache import FileTTLCache
from modules.config import AppConfig
from modules.logging import setup_logging, get_logger
from modules.output_formatter import OutputFormatter
from modules.scan_service import ScanService
from modules.api_server import APIServer

log = get_logger(__name__)


def _load_dotenv(path: str = "/etc/cve-scan-api/scanner.env") -> None:
    """Wczytuje plik .env do os.environ — tylko dla trybu dev (nie nadpisuje istniejących zmiennych).

    W produkcji zmienne są ładowane przez systemd (EnvironmentFile=), więc
    ta funkcja jest wtedy no-op (zmienne już istnieją w os.environ).
    Dla trybu dev wystarczy umieścić plik pod ścieżką
    ``/etc/cve-scan-api/scanner.env`` (tą samą co w scanner.service).
    """
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.split("#")[0].strip()  # usuń komentarze inline
            if key and key not in os.environ:    # nie nadpisuj zmiennych z ENV
                os.environ[key] = value


def main() -> None:
    """Inicjalizuje i uruchamia CVE Scan API."""
    _load_dotenv()

    ap = argparse.ArgumentParser(
        description="CVE Scan API: debsecan + NVD → JSON",
    )
    ap.add_argument("--listen", default=None, help="Adres nasłuchu (nadpisuje ENV CVE_LISTEN)")
    ap.add_argument("--port", type=int, default=None, help="Port (nadpisuje ENV CVE_PORT)")
    args = ap.parse_args()

    cfg = AppConfig.from_env(listen=args.listen, port=args.port)
    setup_logging(cfg)

    log.info("Config: listen=%s port=%s", cfg.listen, cfg.port)
    log.info("NVD_API_KEY: %s", "set" if cfg.nvd_api_key else "not set")
    log.info("CVE_API_TOKEN: %s", "set" if cfg.cve_api_token else "not set")
    log.info(
        "Cache: enabled=%s path=%s ttl=%ss",
        cfg.cache_enabled, cfg.cache_path, cfg.cache_ttl_seconds,
    )

    cache = FileTTLCache(
        path=cfg.cache_path,
        ttl_seconds=cfg.cache_ttl_seconds,
        enabled=cfg.cache_enabled,
    )
    formatter = OutputFormatter()
    scan_service = ScanService(formatter=formatter, cfg=cfg, cache=cache)
    server = APIServer(cfg=cfg, scan_service=scan_service)

    server.serve_forever()


if __name__ == "__main__":
    main()
