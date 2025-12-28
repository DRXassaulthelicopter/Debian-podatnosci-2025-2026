# -*- coding: utf-8 -*-
import json
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from .config import AppConfig
from .constants import PATH_HEALTH, PATH_SCAN
from .errors import BadRequestError, UnauthorizedError
from .logging import get_logger, set_request_id
from .models import ScanRequest
from .scan_service import ScanService

log = get_logger(__name__)


class APIServer:
    def __init__(self, cfg: AppConfig, scan_service: ScanService):
        self.cfg = cfg
        self.scan_service = scan_service

    class _HTTPHandler(BaseHTTPRequestHandler):
        cfg: AppConfig = None  # type: ignore
        scan_service: ScanService = None  # type: ignore
        server_version = "CVE-Scan-API/3.0"

        def _read_json(self) -> Dict[str, Any]:
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
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _require_token(self) -> None:
            required = self.cfg.cve_api_token
            if not required:
                return
            got = self.headers.get("X-API-Token", "")
            if got != required:
                raise UnauthorizedError("Unauthorized")

        def do_GET(self):
            self._maybe_set_request_id()
            parsed = urlparse(self.path)
            if parsed.path == PATH_HEALTH:
                self._send_json(200, {"status": "ok"})
                return
            self._send_json(404, {"error": "Not found"})

        def do_POST(self):
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

                payload = self.scan_service.run(scan_req)  # type: ignore
                self._send_json(200, payload)

            except UnauthorizedError as e:
                self._send_json(401, {"error": str(e)})
            except BadRequestError as e:
                self._send_json(400, {"error": str(e)})
            except Exception as e:
                log.exception("Unhandled error in request: %s", e)
                self._send_json(500, {"error": str(e)})

        def _maybe_set_request_id(self) -> None:
            if self.cfg.log_request_id:
                rid = self.headers.get("X-Request-Id") or str(uuid.uuid4())
                set_request_id(rid)

        def log_message(self, fmt: str, *args):
            # przekieruj logi httpd do loggera
            log.info(fmt, *args)

    def _create_handler(self):
        handler_cls = self._HTTPHandler
        handler_cls.cfg = self.cfg
        handler_cls.scan_service = self.scan_service
        return handler_cls

    def serve_forever(self) -> None:
        httpd = ThreadingHTTPServer((self.cfg.listen, self.cfg.port), self._create_handler())
        log.info("Listening on http://%s:%s", self.cfg.listen, self.cfg.port)
        log.info("GET  %s", PATH_HEALTH)
        log.info("POST %s", PATH_SCAN)
        if self.cfg.cve_api_token:
            log.info("Auth: wymagany nagłówek X-API-Token")
        httpd.serve_forever()
