# -*- coding: utf-8 -*-
"""Łącznik z platformą: pobieranie informacji o hoście i wyników debsecan przez SSH."""

import os
import re
import shlex
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from .errors import SSHCommandError, DebsecanError
from .logging import get_logger

log = get_logger(__name__)

#: Dozwolone nazwy suite Debiana akceptowane przez debsecan.
#: Walidacja blokuje command injection przez parametr ``suite``.
ALLOWED_SUITES: frozenset = frozenset({
    "trixie", "bookworm", "bullseye", "buster", "stretch", "jessie",
    "sid", "unstable", "testing", "stable", "oldstable",
})


class PlatformConnector:
    """Wykonuje zdalne komendy przez SSH (sshpass) na skanowanym hoście Debian.

    Odpowiada za dwie operacje:

    1. :meth:`get_platform_info` — pobiera hostname, FQDN, adresy IP i wersję Debiana.
    2. :meth:`get_findings` — uruchamia ``debsecan --format detail`` i parsuje wynik.

    Uwagi bezpieczeństwa:
        - Parametr ``suite`` jest walidowany względem :data:`ALLOWED_SUITES`.
        - Parametr ``proxy`` jest escapowany przez ``shlex.quote`` przed wstawieniem
          do komendy zdalnej.
        - Hasło przekazywane jest przez zmienną środowiskową ``SSHPASS`` (nie przez
          argumenty CLI, co chroni przed widocznością w ``ps``).
        - ``StrictHostKeyChecking=no`` wyłącza weryfikację klucza hosta — zalecane
          jest zastąpienie tego podejścia kluczami SSH.

    Args:
        host:     Adres IP lub hostname skanowanego hosta.
        user:     Nazwa użytkownika SSH.
        password: Hasło SSH.
        suite:    Nazwa wydania Debiana (musi należeć do ``ALLOWED_SUITES``).
        proxy:    Opcjonalny adres proxy HTTPS dla debsecan.
    """

    def __init__(
        self,
        host: str,
        user: str,
        password: str,
        suite: str,
        proxy: Optional[str] = None,
    ) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.suite = suite
        self.proxy = proxy

    def _ssh_base(self) -> List[str]:
        """Buduje bazową listę argumentów dla sshpass + ssh.

        Hasło jest ustawiane przez zmienną środowiskową ``SSHPASS`` (opcja ``-e``),
        co jest bezpieczniejsze niż przekazywanie go jako argument (``-p``).

        Returns:
            Lista argumentów gotowa do rozszerzenia o komendę zdalną.
        """
        os.environ["SSHPASS"] = self.password
        return [
            "sshpass", "-e", "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            f"{self.user}@{self.host}",
        ]

    def _run_remote(self, remote_cmd: str) -> Tuple[int, str, str]:
        """Wykonuje komendę na zdalnym hoście przez SSH.

        Zmienna ``SSHPASS`` jest usuwana ze środowiska po zakończeniu,
        niezależnie od powodzenia operacji.

        Args:
            remote_cmd: Komenda do wykonania na zdalnym hoście (string — shell zdalny
                        ją interpretuje, więc przekazywane wartości muszą być escapowane).

        Returns:
            Krotka ``(returncode, stdout, stderr)``.

        Raises:
            SSHCommandError: Jeśli ``sshpass`` lub ``ssh`` nie można uruchomić.
        """
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
        """Pobiera informacje o systemie operacyjnym skanowanego hosta.

        Wykonuje zdalny skrypt sh zbierający: hostname, FQDN, adresy IP
        oraz pola z ``/etc/os-release`` (nazwa dystrybucji, wersja, codename).

        Returns:
            Słownik z kluczami ``hostname``, ``fqdn``, ``ip``, ``ip_addresses``
            i ``debian`` (zagnieżdżony słownik z detalami wydania).
            Przy błędzie SSH zwraca częściowy słownik z kluczem ``error``.
        """
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
                "debian": {
                    "suite": self.suite,
                    "pretty_name": None,
                    "version_id": None,
                    "codename": None,
                },
                "error": (err or "").strip() or "Błąd pobierania platform info",
            }

        kv: Dict[str, str] = {}
        for line in out.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                kv[k.strip()] = v.strip()

        ip_list = [x for x in (kv.get("IPS", "").split()) if x.strip()]
        chosen_ip: Optional[str] = None
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
        """Uruchamia ``debsecan --format detail`` na zdalnym hoście.

        Parametr ``suite`` jest walidowany względem :data:`ALLOWED_SUITES`,
        a ``proxy`` escapowany przez ``shlex.quote``, by zapobiec command injection.

        Returns:
            Surowy output debsecan jako string.

        Raises:
            DebsecanError: Jeśli suite jest niedozwolona lub debsecan zwrócił błąd.
        """
        if self.suite not in ALLOWED_SUITES:
            raise DebsecanError(f"Niedozwolona suite: {self.suite!r}")

        suite_arg = shlex.quote(self.suite)
        remote_cmd = f"debsecan --suite {suite_arg} --format detail"
        if self.proxy:
            proxy_arg = shlex.quote(self.proxy)
            remote_cmd = f"https_proxy={proxy_arg} {remote_cmd}"

        rc, out, err = self._run_remote(remote_cmd)
        if rc != 0:
            raise DebsecanError(f"debsecan rc={rc}: {(err or '').strip()}")
        return out

    @staticmethod
    def parse_debsecan_detail(detail_output: str) -> Dict[str, Dict[str, Any]]:
        """Parsuje output debsecan w formacie ``detail`` na słownik podatności.

        Format wejściowy (fragment)::

            CVE-2024-1234 (remote)
              installed: libssl3 3.0.14-1~deb12u1
                         libssl-dev 3.0.14-1~deb12u1

        Wynik — słownik ``{cve_id: {status, packages, raw_installed_lines}}``:

        - ``status``:               tekst w nawiasie po CVE ID lub ``None``.
        - ``packages``:             lista ``{"name": str, "installed_version": str}``.
        - ``raw_installed_lines``:  surowe linie ``installed:`` (do debugowania).

        Duplikaty pakietów w ramach jednego CVE są usuwane.

        Args:
            detail_output: Surowy output debsecan.

        Returns:
            Słownik podatności; pusty słownik, jeśli brak wyników.
        """
        header_re = re.compile(r"^(CVE-\d{4}-\d+)(?:\s+\(([^)]+)\))?\s*$")
        installed_re = re.compile(r"^\s*installed:\s*(.+)\s*$")
        cont_pkg_re = re.compile(r"^\s{10,}(\S+)\s+(.+)\s*$")

        findings: Dict[str, Dict[str, Any]] = {}
        current_cve: Optional[str] = None

        def ensure_cve(cve: str) -> None:
            if cve not in findings:
                findings[cve] = {
                    "cve_id": cve,
                    "status": None,
                    "packages": [],
                    "raw_installed_lines": [],
                }

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
                            findings[current_cve]["packages"].append(
                                {"name": pkg, "installed_version": ver}
                            )

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
                            findings[current_cve]["raw_installed_lines"].append(
                                f"{pkg} {ver}"
                            )
                            findings[current_cve]["packages"].append(
                                {"name": pkg, "installed_version": ver}
                            )
                            j += 1
                            continue
                        break
                    i = j
                    continue

            i += 1

        # Deduplikacja pakietów per CVE (ta sama nazwa + wersja)
        for entry in findings.values():
            seen: set = set()
            uniq = []
            for p in entry.get("packages", []):
                key = (p.get("name"), p.get("installed_version"))
                if key not in seen:
                    seen.add(key)
                    uniq.append(p)
            entry["packages"] = uniq

        return findings

    def get_findings(self) -> Dict[str, Dict[str, Any]]:
        """Pobiera i parsuje wyniki debsecan z zdalnego hosta.

        Returns:
            Słownik ``{cve_id: {...}}`` lub pusty słownik, jeśli debsecan nie zwrócił danych.

        Raises:
            DebsecanError: Jeśli suite jest niedozwolona lub debsecan zwrócił błąd.
            SSHCommandError: Jeśli nie udało się nawiązać połączenia SSH.
        """
        out = self._get_debsecan_detail()
        if not out:
            return {}
        return self.parse_debsecan_detail(out)
