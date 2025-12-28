# -*- coding: utf-8 -*-
from typing import Any, Dict, Optional

import requests

from .cache import FileTTLCache
from .errors import NVDAPIError
from .logging import get_logger

log = get_logger(__name__)


class VulnerabilityDBClient:
    def __init__(
        self,
        *,
        api_key: Optional[str],
        proxy: Optional[str],
        timeout: int,
        base_url: str,
        cache: Optional[FileTTLCache] = None,
    ):
        self.api_key = api_key
        self.proxy = proxy
        self.timeout = int(timeout)
        self.base_url = base_url
        self.cache = cache

    def _build_headers(self) -> Dict[str, str]:
        return {"apiKey": self.api_key} if self.api_key else {}

    def _build_proxies(self) -> Dict[str, str]:
        return {"http": self.proxy, "https": self.proxy} if self.proxy else {}

    def fetch_cvss(self, cve_id: str) -> Optional[Dict[str, Any]]:
        # 1) cache hit
        if self.cache:
            cached = self.cache.get(cve_id)
            if cached is not None:
                return cached

        # 2) NVD
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

            result = {
                "cve_id": cve_id,
                "base_score": cvss.get("baseScore"),
                "severity": cvss.get("baseSeverity", "N/A"),
                "vector": cvss.get("vectorString", "N/A"),
                "exploitability": (metrics or {}).get("exploitabilityScore", "N/A"),
                "impact": (metrics or {}).get("impactScore", "N/A"),
                "score_version": score_version,
            }

            # 3) cache store
            if self.cache:
                try:
                    self.cache.set(cve_id, result)
                except Exception as e:
                    log.warning("cache.set failed for %s: %s", cve_id, e)

            return result

        except Exception as e:
            raise NVDAPIError(f"Błąd NVD dla {cve_id}: {e}", cause=e)
