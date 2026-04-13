# -*- coding: utf-8 -*-
"""Klient NVD API 2.0 pobierający metryki CVSS dla podanego identyfikatora CVE."""

from typing import Any, Dict, Optional

import requests

from .cache import FileTTLCache
from .errors import NVDAPIError
from .logging import get_logger

log = get_logger(__name__)


def _cvssv2_severity(score: float) -> str:
    """Oblicza kategorię severity dla wyniku CVSSv2.

    NVD API 2.0 nie zwraca pola ``baseSeverity`` dla metryk CVSSv2 —
    pole to jest dostępne tylko dla CVSSv3.x i v4.0.
    Progi zgodne z dokumentacją NVD (LOW < 4.0, MEDIUM 4.0–6.9, HIGH ≥ 7.0).

    Args:
        score: Wynik bazowy CVSSv2 (0.0 – 10.0).

    Returns:
        ``"HIGH"``, ``"MEDIUM"`` lub ``"LOW"``.
    """
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


class VulnerabilityDBClient:
    """Klient pobierający metryki CVSS z NVD API v2.0.

    Obsługuje CVSS v4.0, v3.1 i v2 — wybiera najnowszą dostępną wersję
    (v4.0 > v3.1 > v2).  Wyniki są opcjonalnie cache'owane w :class:`~cache.FileTTLCache`.

    Żądania do NVD bez klucza API są objęte limitem ~5 req/30 s.
    Z kluczem limit wzrasta do ~50 req/30 s.

    Args:
        api_key:  Klucz API NVD (``None`` — żądania bez klucza).
        proxy:    Adres proxy HTTPS (``None`` — bezpośrednie połączenie).
        timeout:  Timeout żądań HTTP w sekundach.
        base_url: Bazowy URL NVD API.
        cache:    Instancja cache; ``None`` — brak cache'owania.
    """

    def __init__(
        self,
        *,
        api_key: Optional[str],
        proxy: Optional[str],
        timeout: int,
        base_url: str,
        cache: Optional[FileTTLCache] = None,
    ) -> None:
        self.api_key = api_key
        self.proxy = proxy
        self.timeout = int(timeout)
        self.base_url = base_url
        self.cache = cache

    def _build_headers(self) -> Dict[str, str]:
        """Buduje nagłówki HTTP — dołącza ``apiKey``, jeśli jest dostępny."""
        return {"apiKey": self.api_key} if self.api_key else {}

    def _build_proxies(self) -> Dict[str, str]:
        """Buduje słownik proxy dla biblioteki ``requests``."""
        return {"http": self.proxy, "https": self.proxy} if self.proxy else {}

    def fetch_cvss(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Pobiera metryki CVSS dla podanego CVE ID.

        Kolejność sprawdzania danych z cache i NVD:

        1. Sprawdza cache — jeśli jest trafienie, zwraca je natychmiast.
        2. Wysyła żądanie GET do NVD API.
        3. Wybiera metryki CVSS w kolejności: v4.0 → v3.1 → v2.
        4. Zapisuje wynik w cache.

        Args:
            cve_id: Identyfikator CVE w formacie ``CVE-YYYY-NNNNN``.

        Returns:
            Słownik z kluczami ``base_score``, ``severity``, ``vector``,
            ``exploitability``, ``impact``, ``score_version``
            lub ``None``, jeśli CVE nie istnieje w NVD lub nie ma metryk CVSS.

        Raises:
            NVDAPIError: Przy błędzie HTTP, timeout lub nieprawidłowej odpowiedzi NVD.
        """
        # 1) Sprawdzenie cache
        if self.cache:
            cached = self.cache.get(cve_id)
            if cached is not None:
                return cached

        # 2) Zapytanie do NVD API
        url = "{}?cveId={}".format(self.base_url, cve_id)
        try:
            response = requests.get(
                url,
                headers=self._build_headers(),
                proxies=self._build_proxies(),
                timeout=self.timeout,
            )
            response.raise_for_status()
            data = response.json()

            vulns = data.get("vulnerabilities") or []
            if not vulns:
                return None

            cve_data = vulns[0].get("cve") or {}
            metrics_data = cve_data.get("metrics", {})
            metrics = None
            score_version = None
            cvss: Dict[str, Any] = {}

            # Wybór najnowszej dostępnej wersji CVSS (v4.0 > v3.1 > v2)
            if "cvssMetricV40" in metrics_data:
                ml = metrics_data["cvssMetricV40"] or []
                if ml:
                    metrics = ml[0]
                    cvss = metrics.get("cvssData", {}) or {}
                    score_version = "CVSSv4.0"

            if not cvss and "cvssMetricV31" in metrics_data:
                ml = metrics_data["cvssMetricV31"] or []
                if ml:
                    metrics = ml[0]
                    cvss = metrics.get("cvssData", {}) or {}
                    score_version = "CVSSv3.1"

            if not cvss and "cvssMetricV2" in metrics_data:
                ml = metrics_data["cvssMetricV2"] or []
                if ml:
                    metrics = ml[0]
                    cvss = metrics.get("cvssData", {}) or {}
                    score_version = "CVSSv2"

            if not cvss or "baseScore" not in cvss:
                return None

            base_score = cvss.get("baseScore")

            # CVSSv2 nie ma pola baseSeverity w NVD API 2.0 — obliczamy ręcznie
            if score_version == "CVSSv2":
                severity: Optional[str] = (
                    _cvssv2_severity(float(base_score)) if base_score is not None else None
                )
            else:
                severity = cvss.get("baseSeverity") or None

            result: Dict[str, Any] = {
                "base_score": base_score,
                "severity": severity,
                "vector": cvss.get("vectorString") or None,
                "exploitability": (metrics or {}).get("exploitabilityScore") or None,
                "impact": (metrics or {}).get("impactScore") or None,
                "score_version": score_version,
            }

            # 3) Zapis do cache
            if self.cache:
                try:
                    self.cache.set(cve_id, result)
                except Exception as e:
                    log.warning("cache.set failed for %s: %s", cve_id, e)

            return result

        except Exception as e:
            raise NVDAPIError(f"Błąd NVD dla {cve_id}: {e}", cause=e)
