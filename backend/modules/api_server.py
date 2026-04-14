# -*- coding: utf-8 -*-
"""Wielowątkowy serwer HTTP obsługujący endpointy ``GET /health`` i ``POST /scan``."""

import hmac
import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Type
from urllib.parse import urlparse

from .config import AppConfig
from .constants import PATH_HEALTH, PATH_SCAN
from .errors import BadRequestError, UnauthorizedError
from .logging import get_logger, set_request_id
from .models import ScanRequest
from .scan_service import ScanService

log = get_logger(__name__)


class APIServer:
    """Fasada serwera HTTP — tworzy i konfiguruje ``ThreadingHTTPServer``.

    Przekazuje ``AppConfig`` i ``ScanService`` do handlera przez atrybuty klasowe,
    co jest wymaganym wzorcem dla ``http.server.BaseHTTPRequestHandler``
    (handler jest konstruowany per żądanie, bez możliwości przekazania argumentów
    do konstruktora).

    Args:
        cfg:          Konfiguracja aplikacji.
        scan_service: Instancja usługi skanowania.
    """

    def __init__(self, cfg: AppConfig, scan_service: ScanService) -> None:
        self.cfg = cfg
        self.scan_service = scan_service

    class _HTTPHandler(BaseHTTPRequestHandler):
        """Handler HTTP obsługujący pojedyncze żądanie w osobnym wątku.

        Atrybuty klasowe ``cfg`` i ``scan_service`` są wstrzykiwane przez
        :meth:`APIServer._create_handler` przed uruchomieniem serwera.
        """

        cfg: AppConfig = None  # type: ignore[assignment]
        scan_service: ScanService = None  # type: ignore[assignment]
        server_version = "CVE-Scan-API/3.0"

        def _read_json(self) -> Dict[str, Any]:
            """Odczytuje i parsuje body żądania jako JSON.

            Sprawdza obecność ``Content-Length`` i nieprzekroczenie limitu
            ``cfg.max_body_bytes`` przed odczytem danych.

            Returns:
                Sparsowany słownik JSON.

            Raises:
                BadRequestError: Brak ``Content-Length``, przekroczony limit lub
                                 niepoprawny JSON.
            """
            cl = self.headers.get("Content-Length")
            if not cl:
                raise BadRequestError("Brak Content-Length")
            n = int(cl)
            if n > self.cfg.max_body_bytes:
                raise BadRequestError(f"Body za duże (>{self.cfg.max_body_bytes} B)")
            raw = self.rfile.read(n)
            try:
                return json.loads(raw.decode("utf-8"))
            except Exception as e:
                raise BadRequestError(f"Niepoprawny JSON: {e}", cause=e)

        def _send_json(self, code: int, payload: Dict[str, Any]) -> None:
            """Serializuje ``payload`` do JSON i wysyła odpowiedź HTTP.

            Args:
                code:    Kod statusu HTTP.
                payload: Słownik do serializacji.
            """
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _require_token(self) -> None:
            """Weryfikuje token w nagłówku ``X-API-Token``.

            Porównanie jest odporne na timing attack (``hmac.compare_digest``).
            Jeśli ``cfg.cve_api_token`` jest pusty, autoryzacja jest wyłączona.

            Raises:
                UnauthorizedError: Jeśli token jest nieprawidłowy lub brakuje go.
            """
            required = self.cfg.cve_api_token
            if not required:
                return
            got = self.headers.get("X-API-Token", "")
            if not hmac.compare_digest(got.encode(), required.encode()):
                raise UnauthorizedError("Unauthorized")

        def do_GET(self) -> None:
            """Obsługuje żądania GET.

            ``GET /health`` → ``{"status": "ok"}`` (200).
            Pozostałe ścieżki → 404.
            """
            self._maybe_set_request_id()
            parsed = urlparse(self.path)
            if parsed.path == PATH_HEALTH:
                self._send_json(200, {"status": "ok"})
                return
            self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:
            """Obsługuje żądania POST.

            ``POST /scan`` → uruchamia skanowanie i zwraca wynik (200).

            Wymagane pola body: ``host``, ``user``, ``password``.
            Kody błędów: 400 (złe dane), 401 (zły token), 404 (zła ścieżka),
            500 (nieoczekiwany wyjątek).
            """
            self._maybe_set_request_id()
            parsed = urlparse(self.path)

            try:
                self._require_token()

                if parsed.path != PATH_SCAN:
                    self._send_json(404, {"error": "Not found"})
                    return

                req = self._read_json()

                host = req.get("host")
                user = req.get("user")
                password = req.get("password")
                if not host or not user or not password:
                    raise BadRequestError("Wymagane pola: host, user, password")

                scan_req = ScanRequest(
                    host=host,
                    user=user,
                    password=password,
                    suite=req.get("suite", "trixie"),
                    proxy=(req.get("proxy") or None),
                    api_key=(req.get("api_key") or None),
                    vuln_score=float(req.get("vuln_score", 0.0)),
                    show_unscored=bool(req.get("show_unscored", False)),
                )

                payload = self.scan_service.run(scan_req)  # type: ignore[union-attr]
                self._send_json(200, payload)

            except UnauthorizedError as e:
                self._send_json(401, {"error": str(e)})
            except BadRequestError as e:
                self._send_json(400, {"error": str(e)})
            except Exception as e:
                log.exception("Unhandled error in request: %s", e)
                self._send_json(500, {"error": str(e)})

        def _maybe_set_request_id(self) -> None:
            """Ustawia request-id w kontekście loggera dla bieżącego wątku.

            Używa wartości z nagłówka ``X-Request-Id`` lub generuje nowe UUID.
            Aktywne tylko gdy ``cfg.log_request_id=True``.
            """
            if self.cfg.log_request_id:
                rid = self.headers.get("X-Request-Id") or str(uuid.uuid4())
                set_request_id(rid)

        def log_message(self, fmt: str, *args: Any) -> None:
            """Przekierowuje logi wbudowanego httpd do aplikacyjnego loggera."""
            log.info(fmt, *args)

    def _create_handler(self) -> Type[_HTTPHandler]:
        """Wstrzykuje zależności do klasy handlera i zwraca ją jako fabrykę.

        ``ThreadingHTTPServer`` przyjmuje klasę (nie instancję) handlera —
        ta metoda ustawia atrybuty klasowe przed przekazaniem klasy do serwera.
        """
        handler_cls = self._HTTPHandler
        handler_cls.cfg = self.cfg
        handler_cls.scan_service = self.scan_service
        return handler_cls

    def serve_forever(self) -> None:
        """Uruchamia serwer HTTP i blokuje do momentu przerwania (Ctrl+C / SIGTERM).

        Tworzy instancję ``ThreadingHTTPServer`` i loguje dostępne endpointy.
        """
        httpd = ThreadingHTTPServer(
            (self.cfg.listen, self.cfg.port),
            self._create_handler(),
        )
        log.info("Listening on http://%s:%s", self.cfg.listen, self.cfg.port)
        log.info("GET  %s", PATH_HEALTH)
        log.info("POST %s", PATH_SCAN)
        if self.cfg.cve_api_token:
            log.info("Auth: wymagany nagłówek X-API-Token")
        httpd.serve_forever()
