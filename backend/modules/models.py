# -*- coding: utf-8 -*-
"""Modele danych (dataclasses) opisujące żądania i odpowiedzi API."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanRequest:
    """Parametry pojedynczego żądania skanowania hosta.

    Attributes:
        host:         Adres IP lub hostname skanowanego hosta Debian.
        user:         Nazwa użytkownika SSH.
        password:     Hasło SSH (przekazywane przez sshpass; zalecane TLS + token).
        suite:        Nazwa wydania Debiana dla debsecan (np. ``trixie``, ``bookworm``).
                      Musi należeć do ``platform_connector.ALLOWED_SUITES``.
        proxy:        Adres proxy HTTPS (ustawiany jako ``https_proxy`` dla debsecan
                      i przekazywany do klienta NVD).  ``None`` — brak proxy.
        api_key:      Klucz NVD API per żądanie; nadpisuje wartość z konfiguracji ENV.
                      ``None`` — używany klucz z ``AppConfig.nvd_api_key``.
        vuln_score:   Minimalny próg CVSS (włącznie).  Rekordy z wynikiem poniżej
                      progu są pomijane w odpowiedzi.  Domyślnie ``0.0`` (wszystkie).
        show_unscored: Czy zwracać rekordy CVE, dla których brak danych CVSS lub
                      wystąpił błąd NVD.  Pola CVSS mają wtedy wartość ``null``.
    """

    host: str
    user: str
    password: str
    suite: str = "trixie"
    proxy: Optional[str] = None
    api_key: Optional[str] = None
    vuln_score: float = 0.0
    show_unscored: bool = False
