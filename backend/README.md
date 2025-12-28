# Scanner backend

Serwis HTTP zwracający JSON z:
- informacją o platformie (hostname/FQDN/IP, wersja Debiana)
- listą podatności z `debsecan --format detail`
- metrykami CVSS pobranymi z NVD (CVSS v4.0 / v3.1 / v2)

## Wymagania
Na serwerze API:
- Python 3
- pakiet `requests` (Debian: `python3-requests`)
- `sshpass` (do zdalnego SSH z hasłem w ENV)
- (opcjonalnie) nginx jako reverse proxy

Na hostach skanowanych:
- `debsecan` zainstalowany
- dostęp SSH dla użytkownika, którego podajesz w request

## Struktura projektu
project/
  main.py
  README.md
  modules/
    constants.py
    config.py
    errors.py
    cache.py
    logging.py
    models.py
    platform_connector.py
    vulndb_client.py
    output_formatter.py
    scan_service.py
    api_server.py
  dotfiles/
    scanner.env
    scanner.service
    scanner_nginx.conf


## Uruchomienie (DEV, bez systemd)
```bash
export NVD_API_KEY="..."
export CVE_API_TOKEN="..."
python3 main.py --listen 127.0.0.1 --port 8088
```

### Health:
curl -s http://127.0.0.1:8088/health

## API
### GET /health
Odpowiedź:
```json
{"status":"ok"}
```
### POST /scan
Nagłówki:
 - Content-Type: application/json
 - opcjonalnie: X-API-Token: <token> (jeśli ustawione CVE_API_TOKEN)
 - opcjonalnie: X-Request-Id: <id> (dla korelacji logów; inaczej generowane)

Body:
```json
{
  "host": "192.168.1.177",
  "user": "roman",
  "password": "HASLO_SSH",
  "suite": "trixie",
  "proxy": null,
  "api_key": null,
  "vuln_score": 7.0,
  "show_unscored": false
}
```

Pola:
 - host (required): IP/hostname hosta skanowanego
 - user (required): user SSH
 - password (required): hasło SSH (uwaga bezpieczeństwo!)
 - suite (default: trixie): suite dla debsecan
 - proxy (optional): proxy dla debsecan i NVD (https_proxy)
 - api_key (optional): klucz NVD per request; jeśli brak, użyje ENV NVD_API_KEY
 - vuln_score (default: 0.0): próg CVSS (rekordy poniżej progu są odrzucane)
 - show_unscored (default: false): czy zwracać rekordy bez CVSS / przy błędach NVD

Odpowiedź:
```json
{
  "platform": {
    "hostname": "raspberrypi",
    "fqdn": "raspberrypi",
    "ip": "192.168.1.177",
    "ip_addresses": ["192.168.1.177", "fdxx:..."],
    "debian": {
      "suite": "trixie",
      "pretty_name": "Debian GNU/Linux 13 (trixie)",
      "version_id": "13",
      "codename": "trixie"
    }
  },
  "vulnerabilities": [
    {
      "cve_id": "CVE-2013-7445",
      "debsecan_status": "unknown",
      "affected_packages": [
        {"name":"linux-image-...", "installed_version":"1:6.12.47-1+rpt1"}
      ],
      "base_score": 7.8,
      "severity": "N/A",
      "vector": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
      "exploitability": 10.0,
      "impact": 6.9,
      "score_version": "CVSSv2"
    }
  ],
  "summary": {
    "threshold_cvss": 7.0,
    "matched_cvss_ge_threshold": 1,
    "cvss_versions_used": {"v4.0":0,"v3.1":0,"v2":1},
    "no_cvss_metrics": 0,
    "parse_errors": 0,
    "total_cves_seen": 42,
    "total_records_output": 1
  }
}
```

## Cache NVD
NVD jest cache’owane per cve_id w pliku JSON (TTL).
ENV:
 - CVE_CACHE_ENABLED=1
 - CVE_CACHE_PATH=/var/cache/cve-scan-api/nvd_cache.json
 - CVE_CACHE_TTL=86400

### Security notes

Wysyłanie hasła SSH w body JSON jest wygodne, ale słabe bezpieczeństwo.
Zalecenia:
 - trzymanie API za nginx + TLS
 - włączenie CVE_API_TOKEN
 - ograniczenie dostępu firewall’em
 - docelowo: przejść na SSH key auth zamiast password

### Deploy (systemd + nginx)
 - Unit: /etc/systemd/system/cve-scan-api.service
 - ENV: /etc/cve-scan-api/cve-scan-api.env (chmod 600)
 - nginx: /etc/nginx/sites-available/cve-scan-api.conf

Start/stop:
```bash
sudo systemctl enable --now cve-scan-api
sudo systemctl restart cve-scan-api
journalctl -u cve-scan-api -f
```

### Test (curl)
```bash
curl -s http://cve-api.example.local/health

curl -s -X POST http://cve-api.example.local/scan \
  -H 'Content-Type: application/json' \
  -H 'X-API-Token: <token>' \
  -d '{
    "host":"192.168.1.177",
    "user":"roman",
    "password":"HASLO",
    "suite":"trixie",
    "vuln_score":7.0,
    "show_unscored":false
  }'
```

### Test (PowerShell)
```powershell
$uri = "http://cve-api.example.local/scan"
$body = @{
  host = "192.168.1.177"
  user = "roman"
  password = "HASLO"
  suite = "trixie"
  vuln_score = 7.0
  show_unscored = $false
} | ConvertTo-Json -Depth 10

Invoke-RestMethod -Method Post -Uri $uri -ContentType "application/json" -Headers @{
  "X-API-Token" = "<token>"
} -Body $body | ConvertTo-Json -Depth 10
```

## Troubleshooting
 - 401 Unauthorized: brak/niepoprawny X-API-Token (gdy CVE_API_TOKEN ustawiony)
 - 500: sprawdź journalctl -u scanner -f
 - brak CVE: upewnij się że debsecan jest na hoście i działa dla podanej suite
 - sshpass missing: doinstaluj sshpass na serwerze API

