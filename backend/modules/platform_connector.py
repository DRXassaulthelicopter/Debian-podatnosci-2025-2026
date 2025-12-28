# -*- coding: utf-8 -*-
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .errors import SSHCommandError, DebsecanError
from .logging import get_logger

log = get_logger(__name__)


class PlatformConnector:
    def __init__(self, host: str, user: str, password: str, suite: str, proxy: Optional[str] = None):
        self.host = host
        self.user = user
        self.password = password
        self.suite = suite
        self.proxy = proxy

    def _ssh_base(self) -> List[str]:
        os.environ["SSHPASS"] = self.password
        return [
            "sshpass", "-e", "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            f"{self.user}@{self.host}",
        ]

    def _run_remote(self, remote_cmd: str) -> Tuple[int, str, str]:
        ssh_cmd = self._ssh_base() + [remote_cmd]
        try:
            proc = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
            )
            out, err = proc.communicate()
            return proc.returncode, out, err
        except OSError as e:
            raise SSHCommandError("sshpass/ssh nie znaleziony lub nie da się uruchomić", cause=e)
        finally:
            if "SSHPASS" in os.environ:
                del os.environ["SSHPASS"]

    def get_platform_info(self) -> Dict[str, Any]:
        remote_cmd = r"""sh -c '
set -e
HN="$(hostname 2>/dev/null || echo unknown)"
FQDN="$(hostname -f 2>/dev/null || echo "$HN")"
IPS="$(hostname -I 2>/dev/null || true)"
if [ -z "$IPS" ]; then
  IPS="$(ip -4 -o addr show scope global 2>/dev/null | awk "{print \$4}" | cut -d/ -f1 | tr "\n" " " || true)"
fi

PRETTY=""
VID=""
VCODE=""
if [ -r /etc/os-release ]; then
  . /etc/os-release
  PRETTY="${PRETTY_NAME:-}"
  VID="${VERSION_ID:-}"
  VCODE="${VERSION_CODENAME:-${UBUNTU_CODENAME:-}}"
fi

echo "HOSTNAME=$HN"
echo "FQDN=$FQDN"
echo "IPS=$IPS"
echo "DEBIAN_PRETTY=$PRETTY"
echo "DEBIAN_VERSION_ID=$VID"
echo "DEBIAN_CODENAME=$VCODE"
'"""
        rc, out, err = self._run_remote(remote_cmd)
        if rc != 0:
            log.warning("get_platform_info rc=%s err=%s", rc, (err or "").strip())
            return {
                "hostname": None,
                "fqdn": None,
                "ip": None,
                "ip_addresses": [],
                "debian": {"suite": self.suite, "pretty_name": None, "version_id": None, "codename": None},
                "error": (err or "").strip() or "Błąd pobierania platform info",
            }

        kv: Dict[str, str] = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()

        ip_list = [x for x in (kv.get("IPS", "").split()) if x.strip()]
        chosen_ip = None
        for ip in ip_list:
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                chosen_ip = ip
                break
        if not chosen_ip and ip_list:
            chosen_ip = ip_list[0]

        return {
            "hostname": kv.get("HOSTNAME") or None,
            "fqdn": kv.get("FQDN") or None,
            "ip": chosen_ip,
            "ip_addresses": ip_list,
            "debian": {
                "suite": self.suite,
                "pretty_name": kv.get("DEBIAN_PRETTY") or None,
                "version_id": kv.get("DEBIAN_VERSION_ID") or None,
                "codename": kv.get("DEBIAN_CODENAME") or None,
            },
        }

    def _get_debsecan_detail(self) -> str:
        remote_cmd = f"debsecan --suite {self.suite} --format detail"
        if self.proxy:
            remote_cmd = f"https_proxy={self.proxy} {remote_cmd}"

        rc, out, err = self._run_remote(remote_cmd)
        if rc != 0:
            raise DebsecanError(f"debsecan rc={rc}: {(err or '').strip()}")
        return out

    @staticmethod
    def parse_debsecan_detail(detail_output: str) -> Dict[str, Dict[str, Any]]:
        header_re = re.compile(r"^(CVE-\d{4}-\d+)(?:\s+\(([^)]+)\))?\s*$")
        installed_re = re.compile(r"^\s*installed:\s*(.+)\s*$")
        cont_pkg_re = re.compile(r"^\s{10,}(\S+)\s+(.+)\s*$")

        findings: Dict[str, Dict[str, Any]] = {}
        current_cve: Optional[str] = None

        def ensure_cve(cve: str):
            if cve not in findings:
                findings[cve] = {"cve_id": cve, "status": None, "packages": [], "raw_installed_lines": []}

        lines = detail_output.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i]
            m = header_re.match(line.strip())
            if m:
                current_cve = m.group(1)
                status = (m.group(2) or "").strip() or None
                ensure_cve(current_cve)
                findings[current_cve]["status"] = status
                i += 1
                continue

            if current_cve:
                mi = installed_re.match(line)
                if mi:
                    raw = mi.group(1).strip()
                    findings[current_cve]["raw_installed_lines"].append(raw)

                    parts = raw.split()
                    if parts:
                        pkg = parts[0]
                        ver = " ".join(parts[1:]).strip() or None
                        if ver:
                            findings[current_cve]["packages"].append({"name": pkg, "installed_version": ver})

                    i += 1
                    j = i
                    while j < len(lines):
                        nxt = lines[j]
                        if nxt.strip().startswith("("):
                            j += 1
                            continue
                        mc = cont_pkg_re.match(nxt)
                        if mc:
                            pkg = mc.group(1).strip()
                            ver = mc.group(2).strip()
                            if pkg.lower() in {"fixed", "fix", "package", "branch"}:
                                break
                            if not re.match(r"^[a-z0-9][a-z0-9+.-]+$", pkg):
                                break
                            findings[current_cve]["raw_installed_lines"].append(f"{pkg} {ver}")
                            findings[current_cve]["packages"].append({"name": pkg, "installed_version": ver})
                            j += 1
                            continue
                        break
                    i = j
                    continue

            i += 1

        # dedupe paczek
        for cve_id, entry in findings.items():
            seen = set()
            uniq = []
            for p in entry.get("packages", []):
                key = (p.get("name"), p.get("installed_version"))
                if key not in seen:
                    seen.add(key)
                    uniq.append(p)
            entry["packages"] = uniq

        return findings

    def get_findings(self) -> Dict[str, Dict[str, Any]]:
        out = self._get_debsecan_detail()
        if not out:
            return {}
        return self.parse_debsecan_detail(out)
