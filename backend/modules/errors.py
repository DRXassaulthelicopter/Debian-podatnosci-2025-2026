# -*- coding: utf-8 -*-
from typing import Optional


class CVEAPIError(Exception):
    """Bazowy wyjątek aplikacji."""
    def __init__(self, message: str, *, cause: Optional[BaseException] = None):
        super().__init__(message)
        self.cause = cause


class BadRequestError(CVEAPIError):
    """400 - błędne dane wejściowe."""


class UnauthorizedError(CVEAPIError):
    """401 - brak autoryzacji."""


class PlatformError(CVEAPIError):
    """Błędy platformy (SSH/debsecan)."""


class SSHCommandError(PlatformError):
    """SSH / uruchamianie komend zdalnych."""


class DebsecanError(PlatformError):
    """Debsecan nie działa / błąd wykonania / dziwny output."""


class VulnerabilityDBError(CVEAPIError):
    """Błędy bazy podatności (NVD)."""


class NVDAPIError(VulnerabilityDBError):
    """Błąd zapytań/odpowiedzi NVD."""


class CacheError(CVEAPIError):
    """Błędy cache (IO/format)."""
