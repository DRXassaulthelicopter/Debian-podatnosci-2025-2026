#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse

from modules.cache import FileTTLCache
from modules.config import AppConfig
from modules.logging import setup_logging, get_logger
from modules.output_formatter import OutputFormatter
from modules.scan_service import ScanService
from modules.api_server import APIServer

log = get_logger(__name__)


def main():
    ap = argparse.ArgumentParser(description="HTTP API: debsecan+NVD -> JSON (moduły, cache, config, logging)")
    ap.add_argument("--listen", default=None, help="Adres nasłuchu (nadpisuje ENV)")
    ap.add_argument("--port", type=int, default=None, help="Port (nadpisuje ENV)")
    args = ap.parse_args()

    cfg = AppConfig.from_env(listen=args.listen, port=args.port)
    setup_logging(cfg)

    log.info("Config: listen=%s port=%s", cfg.listen, cfg.port)
    log.info("NVD_API_KEY: %s", "set" if cfg.nvd_api_key else "not set")
    log.info("CVE_API_TOKEN: %s", "set" if cfg.cve_api_token else "not set")
    log.info("Cache: enabled=%s path=%s ttl=%ss", cfg.cache_enabled, cfg.cache_path, cfg.cache_ttl_seconds)

    cache = FileTTLCache(path=cfg.cache_path, ttl_seconds=cfg.cache_ttl_seconds, enabled=cfg.cache_enabled)
    formatter = OutputFormatter()
    scan_service = ScanService(formatter=formatter, cfg=cfg, cache=cache)
    server = APIServer(cfg=cfg, scan_service=scan_service)

    server.serve_forever()


if __name__ == "__main__":
    main()
