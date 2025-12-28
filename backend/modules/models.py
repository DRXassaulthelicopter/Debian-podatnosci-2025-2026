# -*- coding: utf-8 -*-
from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanRequest:
    host: str
    user: str
    password: str
    suite: str = "trixie"
    proxy: Optional[str] = None
    api_key: Optional[str] = None
    vuln_score: float = 0.0
    show_unscored: bool = False
