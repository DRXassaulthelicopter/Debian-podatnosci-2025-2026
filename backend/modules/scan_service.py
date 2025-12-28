# -*- coding: utf-8 -*-
from typing import Any, Dict, List

from .cache import FileTTLCache
from .config import AppConfig
from .errors import PlatformError, VulnerabilityDBError
from .models import ScanRequest
from .output_formatter import OutputFormatter
from .platform_connector import PlatformConnector
from .vulndb_client import VulnerabilityDBClient
from .logging import get_logger

log = get_logger(__name__)


class ScanService:
    def __init__(self, formatter: OutputFormatter, cfg: AppConfig, cache: FileTTLCache):
        self.formatter = formatter
        self.cfg = cfg
        self.cache = cache

    def run(self, req: ScanRequest) -> Dict[str, Any]:
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

        # platform info (nawet jak findings padną, chcemy to zwrócić)
        try:
            platform = platform_client.get_platform_info()
        except Exception as e:
            platform = {
                "hostname": None, "fqdn": None, "ip": None, "ip_addresses": [],
                "debian": {"suite": req.suite, "pretty_name": None, "version_id": None, "codename": None},
                "error": str(e),
            }

        # findings z debsecan
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
                if req.show_unscored:
                    rec = dict(base_record)
                    rec.update({
                        "base_score": None,
                        "severity": "N/A",
                        "vector": "N/A",
                        "exploitability": "N/A",
                        "impact": "N/A",
                        "score_version": "Brak danych",
                        "error": str(e),
                    })
                    vulnerabilities.append(rec)
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

                        rec = dict(base_record)
                        rec.update(info)
                        vulnerabilities.append(rec)
                except Exception:
                    parse_errors += 1
            else:
                no_score += 1
                if req.show_unscored:
                    rec = dict(base_record)
                    rec.update({
                        "base_score": None,
                        "severity": "N/A",
                        "vector": "N/A",
                        "exploitability": "N/A",
                        "impact": "N/A",
                        "score_version": "Brak danych",
                    })
                    vulnerabilities.append(rec)

        summary = {
            "threshold_cvss": req.vuln_score,
            "matched_cvss_ge_threshold": matched,
            "cvss_versions_used": {"v4.0": cvss_v4_used, "v3.1": cvss_v3_used, "v2": cvss_v2_used},
            "no_cvss_metrics": no_score,
            "parse_errors": parse_errors,
            "total_cves_seen": len(cve_ids),
            "total_records_output": len(vulnerabilities),
        }

        return self.formatter.build_payload(platform, vulnerabilities, summary)

