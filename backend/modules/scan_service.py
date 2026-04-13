# -*- coding: utf-8 -*-
"""Logika orkiestracji skanowania: SSH → debsecan → NVD → ujednolicona odpowiedź."""

from typing import Any, Dict, List, Optional

from .cache import FileTTLCache
from .config import AppConfig
from .errors import PlatformError, VulnerabilityDBError
from .models import ScanRequest
from .output_formatter import OutputFormatter
from .platform_connector import PlatformConnector
from .vulndb_client import VulnerabilityDBClient
from .logging import get_logger

log = get_logger(__name__)

#: Pola CVSS obecne w każdym rekordzie podatności — ``None`` gdy dane niedostępne.
_VULN_FIELDS = ("base_score", "severity", "vector", "exploitability", "impact", "score_version")


def _build_vuln_record(
    base: Dict[str, Any],
    info: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Buduje rekord podatności z jednolitym, stałym zestawem pól.

    Każdy wpis tablicy ``vulnerabilities`` w odpowiedzi API ma dokładnie te same
    klucze, niezależnie od tego czy dane CVSS są dostępne.  Brakujące wartości
    są reprezentowane przez ``null`` (Python ``None``), nie przez ciągi ``"N/A"``.

    Args:
        base:  Bazowe pola rekordu: ``cve_id``, ``debsecan_status``, ``affected_packages``.
        info:  Słownik z metrykami CVSS zwrócony przez :meth:`~vulndb_client.VulnerabilityDBClient.fetch_cvss`.
               ``None`` gdy brak danych lub błąd NVD.
        error: Komunikat błędu NVD do wstawienia w pole ``error``.
               ``None`` gdy operacja zakończyła się sukcesem.

    Returns:
        Gotowy słownik rekordu podatności.
    """
    rec = dict(base)
    if info is not None:
        for field in _VULN_FIELDS:
            rec[field] = info.get(field)
        rec["error"] = None
    else:
        for field in _VULN_FIELDS:
            rec[field] = None
        rec["error"] = error
    return rec


class ScanService:
    """Orkiestrator procesu skanowania podatności.

    Łączy trzy warstwy:

    1. :class:`~platform_connector.PlatformConnector` — SSH + debsecan.
    2. :class:`~vulndb_client.VulnerabilityDBClient` — metryki CVSS z NVD.
    3. :class:`~output_formatter.OutputFormatter` — budowanie odpowiedzi JSON.

    Wyniki są filtrowane przez próg ``vuln_score`` z :class:`~models.ScanRequest`.
    CVE bez metryk CVSS są opcjonalnie dołączane gdy ``show_unscored=True``.

    Args:
        formatter: Instancja formatera odpowiedzi.
        cfg:       Konfiguracja aplikacji.
        cache:     Cache NVD (może być wyłączony przez ``cfg.cache_enabled=False``).
    """

    def __init__(
        self,
        formatter: OutputFormatter,
        cfg: AppConfig,
        cache: FileTTLCache,
    ) -> None:
        self.formatter = formatter
        self.cfg = cfg
        self.cache = cache

    def run(self, req: ScanRequest) -> Dict[str, Any]:
        """Wykonuje pełny cykl skanowania dla podanego żądania.

        Przebieg:

        1. Pobiera informacje o platformie przez SSH (błąd nie przerywa skanowania).
        2. Uruchamia ``debsecan --format detail`` — błąd zwraca odpowiedź z pustą listą.
        3. Dla każdego CVE pobiera metryki CVSS z NVD (z cache lub bezpośrednio).
        4. Filtruje wyniki przez ``req.vuln_score``.
        5. Zbiera statystyki i zwraca ustrukturyzowaną odpowiedź.

        Args:
            req: Parametry skanowania (host, credentials, progi, opcje).

        Returns:
            Słownik z kluczami ``platform``, ``vulnerabilities`` i ``summary``,
            gotowy do serializacji przez ``json.dumps``.
        """
        platform_client = PlatformConnector(
            host=req.host,
            user=req.user,
            password=req.password,
            suite=req.suite,
            proxy=req.proxy,
        )

        vuln_client = VulnerabilityDBClient(
            api_key=req.api_key or self.cfg.nvd_api_key,
            proxy=req.proxy,
            timeout=self.cfg.http_timeout_seconds,
            base_url=self.cfg.nvd_base_url,
            cache=self.cache,
        )

        # Informacje o platformie — błąd SSH nie przerywa skanowania CVE.
        try:
            platform = platform_client.get_platform_info()
        except Exception as e:
            platform = {
                "hostname": None, "fqdn": None, "ip": None, "ip_addresses": [],
                "debian": {
                    "suite": req.suite,
                    "pretty_name": None,
                    "version_id": None,
                    "codename": None,
                },
                "error": str(e),
            }

        # Wyniki debsecan — błąd zwraca odpowiedź z pustą listą podatności.
        try:
            findings_map = platform_client.get_findings()
        except PlatformError as e:
            return self.formatter.build_payload(platform, [], {"error": str(e)})

        cve_ids = sorted(findings_map.keys()) if findings_map else []

        matched = 0
        no_score = 0
        parse_errors = 0
        cvss_v2_used = 0
        cvss_v3_used = 0
        cvss_v4_used = 0

        vulnerabilities: List[Dict[str, Any]] = []

        for cve_id in cve_ids:
            deb_entry = findings_map.get(cve_id, {})
            pkgs = deb_entry.get("packages", [])
            deb_status = deb_entry.get("status")

            base_record: Dict[str, Any] = {
                "cve_id": cve_id,
                "debsecan_status": deb_status or "unknown",
                "affected_packages": pkgs,
            }

            try:
                info = vuln_client.fetch_cvss(cve_id)
            except VulnerabilityDBError as e:
                # Błąd NVD — opcjonalnie dołącz rekord z null-ami i komunikatem błędu.
                if req.show_unscored:
                    vulnerabilities.append(_build_vuln_record(base_record, error=str(e)))
                continue

            if info and info.get("base_score") is not None:
                try:
                    score = float(info["base_score"])
                    if score >= req.vuln_score:
                        matched += 1
                        version = info.get("score_version")
                        if version == "CVSSv2":
                            cvss_v2_used += 1
                        elif version == "CVSSv3.1":
                            cvss_v3_used += 1
                        elif version == "CVSSv4.0":
                            cvss_v4_used += 1

                        vulnerabilities.append(_build_vuln_record(base_record, info=info))
                except Exception:
                    parse_errors += 1
            else:
                no_score += 1
                if req.show_unscored:
                    vulnerabilities.append(_build_vuln_record(base_record))

        summary: Dict[str, Any] = {
            "threshold_cvss": req.vuln_score,
            "matched_cvss_ge_threshold": matched,
            "cvss_versions_used": {
                "v4.0": cvss_v4_used,
                "v3.1": cvss_v3_used,
                "v2": cvss_v2_used,
            },
            "no_cvss_metrics": no_score,
            "parse_errors": parse_errors,
            "total_cves_seen": len(cve_ids),
            "total_records_output": len(vulnerabilities),
        }

        return self.formatter.build_payload(platform, vulnerabilities, summary)
