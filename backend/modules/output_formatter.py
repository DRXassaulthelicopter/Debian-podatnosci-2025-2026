# -*- coding: utf-8 -*-
from typing import Any, Dict, List


class OutputFormatter:
    @staticmethod
    def build_payload(platform: Dict[str, Any], vulnerabilities: List[Dict[str, Any]], summary: Dict[str, Any]) -> Dict[str, Any]:
        return {"platform": platform, "vulnerabilities": vulnerabilities, "summary": summary}
