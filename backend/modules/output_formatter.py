# -*- coding: utf-8 -*-
"""Formatowanie odpowiedzi JSON zwracanej przez endpoint ``POST /scan``."""

from typing import Any, Dict, List


class OutputFormatter:
    """Składa końcowy payload odpowiedzi API ze składowych sekcji.

    Centralizuje strukturę odpowiedzi, dzięki czemu ``ScanService``
    nie zna formatu JSON — tylko przekazuje dane.
    """

    @staticmethod
    def build_payload(
        platform: Dict[str, Any],
        vulnerabilities: List[Dict[str, Any]],
        summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Buduje słownik odpowiedzi API.

        Args:
            platform:        Informacje o skanowanym hoście (hostname, IP, wersja Debiana).
            vulnerabilities: Lista rekordów podatności — każdy ma jednolity zestaw pól.
            summary:         Statystyki skanowania (liczniki, progi CVSS itp.).

        Returns:
            Słownik gotowy do serializacji przez ``json.dumps``.
        """
        return {
            "platform": platform,
            "vulnerabilities": vulnerabilities,
            "summary": summary,
        }
