# -*- coding: utf-8 -*-
"""Hierarchia wyjątków aplikacji CVE Scan API."""

from typing import Optional


class CVEAPIError(Exception):
    """Bazowy wyjątek aplikacji.

    Wszystkie wyjątki domenowe dziedziczą po tej klasie,
    co pozwala na jedną klauzulę ``except CVEAPIError`` tam gdzie potrzeba.

    Attributes:
        cause: Oryginalny wyjątek, który spowodował ten błąd (jeśli dostępny).
    """

    def __init__(self, message: str, *, cause: Optional[BaseException] = None) -> None:
        super().__init__(message)
        self.cause = cause


class BadRequestError(CVEAPIError):
    """400 — niepoprawne lub niekompletne dane wejściowe żądania."""


class UnauthorizedError(CVEAPIError):
    """401 — brak lub nieprawidłowy token autoryzacyjny."""


class PlatformError(CVEAPIError):
    """Błędy warstwy platformy (SSH / debsecan)."""


class SSHCommandError(PlatformError):
    """Nie udało się uruchomić sshpass/ssh lub połączyć z hostem."""


class DebsecanError(PlatformError):
    """Debsecan zwrócił błąd, nie uruchomił się lub jego output jest nieprawidłowy."""


class VulnerabilityDBError(CVEAPIError):
    """Błędy komunikacji z bazą podatności (NVD)."""


class NVDAPIError(VulnerabilityDBError):
    """Błąd żądania HTTP do NVD API lub parsowania odpowiedzi."""


class CacheError(CVEAPIError):
    """Błąd operacji cache (odczyt/zapis pliku lub nieprawidłowy format)."""
