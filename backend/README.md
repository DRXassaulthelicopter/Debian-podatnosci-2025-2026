# CVE Scan API — backend

Serwis HTTP skanujący hosty Debian pod kątem podatności.  
Łączy wyniki `debsecan --format detail` z metrykami CVSS pobranymi z NVD API 2.0
i zwraca ujednolicony JSON.

## Wymagania

**Na serwerze API:**
- Python ≥ 3.7
- `pip install -r requirements.txt` (jedyna zewnętrzna zależność: `requests`)
- `sshpass` — do uwierzytelnienia SSH hasłem (`apt install sshpass`)
- (opcjonalnie) nginx jako reverse proxy z TLS

**Na każdym skanowanym hoście:**
- `debsecan` — (`apt install debsecan`)
- Dostęp SSH dla użytkownika podawanego w żądaniu

## Struktura projektu

```
backend/
├── main.py                   # punkt wejścia
├── requirements.txt
├── modules/
│   ├── constants.py          # nazwy ENV i wartości domyślne
│   ├── config.py             # AppConfig (frozen dataclass, walidacja)
│   ├── errors.py             # hierarchia wyjątków
│   ├── models.py             # ScanRequest (dataclass)
│   ├── cache.py              # FileTTLCache — plikowy cache NVD (JSON, TTL)
│   ├── logging.py            # setup loggera, JSON formatter, request-id
│   ├── output_formatter.py   # budowanie payloadu odpowiedzi
│   ├── platform_connector.py # SSH + debsecan + parser outputu
│   ├── vulndb_client.py      # klient NVD API 2.0 (CVSS v4/v3.1/v2)
│   ├── scan_service.py       # orkiestrator skanowania
│   └── api_server.py         # ThreadingHTTPServer, handlery GET/POST
└── dotfiles/
    ├── scanner.env           # szablon zmiennych środowiskowych
    ├── scanner.service       # unit systemd
    └── scanner_nginx.conf    # konfiguracja nginx (reverse proxy)
```

## Uruchomienie (dev, bez systemd)

```bash
pip install -r requirements.txt

export NVD_API_KEY="twój-klucz-nvd"       # https://nvd.nist.gov/developers/request-an-api-key
export CVE_API_TOKEN="losowy-długi-token"  # opcjonalne, ale zalecane

python3 main.py --listen 127.0.0.1 --port 8088
```

## Zmienne środowiskowe

| Zmienna             | Domyślna               | Opis                                              |
|---------------------|------------------------|---------------------------------------------------|
| `NVD_API_KEY`       | —                      | Klucz API NVD (bez klucza: limit 5 req/30 s)      |
| `CVE_API_TOKEN`     | —                      | Token `X-API-Token`; brak = autoryzacja wyłączona |
| `CVE_LISTEN`        | `127.0.0.1`            | Adres nasłuchu serwera HTTP                       |
| `CVE_PORT`          | `8088`                 | Port serwera HTTP                                 |
| `CVE_MAX_BODY`      | `1048576`              | Maks. rozmiar body żądania (bajty)                |
| `CVE_CACHE_ENABLED` | `1`                    | Włącz/wyłącz cache NVD (`1`/`0`)                  |
| `CVE_CACHE_PATH`    | `nvd_cache.json`       | Ścieżka do pliku JSON cache                       |
| `CVE_CACHE_TTL`     | `86400`                | TTL wpisów cache (sekundy)                        |
| `CVE_HTTP_TIMEOUT`  | `15`                   | Timeout żądań HTTP do NVD (sekundy)               |
| `CVE_NVD_BASE_URL`  | `https://services…`    | Nadpisanie URL NVD API (testy / mirror)           |
| `CVE_LOG_LEVEL`     | `INFO`                 | Poziom logowania (DEBUG/INFO/WARNING/ERROR)        |
| `CVE_LOG_JSON`      | `0`                    | Format logów JSON (`1`/`0`)                       |
| `CVE_LOG_REQUEST_ID`| `1`                    | Dołączaj `request_id` do logów (`1`/`0`)          |

## API

### GET /health

Sprawdzenie dostępności serwisu.

```
GET /health
```

Odpowiedź `200 OK`:
```json
{"status": "ok"}
```

---

### POST /scan

Uruchamia skanowanie hosta i zwraca listę podatności z metrykami CVSS.

```
POST /scan
Content-Type: application/json
X-API-Token: <token>          (wymagany gdy CVE_API_TOKEN ustawiony)
X-Request-Id: <uuid>          (opcjonalny; inaczej generowany automatycznie)
```

**Body żądania:**

```json
{
  "host":         "192.168.1.10",
  "user":         "admin",
  "password":     "hasło_ssh",
  "suite":        "trixie",
  "proxy":        null,
  "api_key":      null,
  "vuln_score":   7.0,
  "show_unscored": false
}
```

| Pole           | Typ     | Wymagane | Domyślna | Opis                                                            |
|----------------|---------|----------|----------|-----------------------------------------------------------------|
| `host`         | string  | tak      | —        | IP lub hostname skanowanego hosta                               |
| `user`         | string  | tak      | —        | Nazwa użytkownika SSH                                           |
| `password`     | string  | tak      | —        | Hasło SSH                                                       |
| `suite`        | string  | nie      | `trixie` | Wydanie Debiana (`trixie`, `bookworm`, `bullseye`, `buster` …)  |
| `proxy`        | string  | nie      | `null`   | Proxy HTTPS dla debsecan i NVD (`https://host:port`)            |
| `api_key`      | string  | nie      | `null`   | Klucz NVD per żądanie (nadpisuje `NVD_API_KEY` z ENV)           |
| `vuln_score`   | number  | nie      | `0.0`    | Minimalny próg CVSS (włącznie); rekordy poniżej są pomijane     |
| `show_unscored`| boolean | nie      | `false`  | Zwracaj CVE bez danych CVSS lub przy błędzie NVD (pola = null)  |

**Odpowiedź `200 OK`:**

```json
{
  "platform": {
    "hostname": "raspberrypi",
    "fqdn": "raspberrypi.local",
    "ip": "192.168.1.10",
    "ip_addresses": ["192.168.1.10"],
    "debian": {
      "suite": "trixie",
      "pretty_name": "Debian GNU/Linux 13 (trixie)",
      "version_id": "13",
      "codename": "trixie"
    }
  },
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-1234",
      "debsecan_status": "remote",
      "affected_packages": [
        {"name": "libssl3", "installed_version": "3.0.14-1~deb12u1"}
      ],
      "base_score": 9.8,
      "severity": "CRITICAL",
      "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "exploitability": 3.9,
      "impact": 5.9,
      "score_version": "CVSSv3.1",
      "error": null
    },
    {
      "cve_id": "CVE-2013-7445",
      "debsecan_status": "unknown",
      "affected_packages": [
        {"name": "linux-image-6.12.0-1", "installed_version": "1:6.12.47-1"}
      ],
      "base_score": 7.8,
      "severity": "HIGH",
      "vector": "AV:N/AC:L/Au:N/C:N/I:N/A:C",
      "exploitability": 10.0,
      "impact": 6.9,
      "score_version": "CVSSv2",
      "error": null
    }
  ],
  "summary": {
    "threshold_cvss": 7.0,
    "matched_cvss_ge_threshold": 2,
    "cvss_versions_used": {"v4.0": 0, "v3.1": 1, "v2": 1},
    "no_cvss_metrics": 5,
    "parse_errors": 0,
    "total_cves_seen": 42,
    "total_records_output": 2
  }
}
```

> **Uwaga:** Każdy rekord w tablicy `vulnerabilities` ma zawsze ten sam zestaw pól.
> Gdy brak danych CVSS (lub błąd NVD), pola `base_score`–`score_version` mają wartość `null`,
> a pole `error` zawiera komunikat błędu.

**Kody błędów:**

| Kod | Przyczyna                                         |
|-----|---------------------------------------------------|
| 400 | Brak wymaganych pól (`host`/`user`/`password`), niepoprawny JSON lub przekroczony limit body |
| 401 | Brak lub nieprawidłowy `X-API-Token`              |
| 404 | Nieznana ścieżka                                  |
| 500 | Nieoczekiwany błąd wewnętrzny (szczegóły w logach)|

## Deploy (systemd + nginx)

```
/etc/systemd/system/cve-scan-api.service   ← dotfiles/scanner.service
/etc/cve-scan-api/scanner.env              ← dotfiles/scanner.env  (chmod 600)
/etc/nginx/sites-available/cve-scan-api    ← dotfiles/scanner_nginx.conf
/opt/cve-scan-api/                         ← kod aplikacji
/var/cache/cve-scan-api/nvd_cache.json     ← cache NVD (tworzony automatycznie)
```

```bash
# Instalacja
sudo mkdir -p /opt/cve-scan-api /etc/cve-scan-api /var/cache/cve-scan-api
sudo cp -r . /opt/cve-scan-api/
sudo pip3 install -r /opt/cve-scan-api/requirements.txt

# Konfiguracja
sudo cp dotfiles/scanner.env /etc/cve-scan-api/scanner.env
sudo chmod 600 /etc/cve-scan-api/scanner.env
# Edytuj /etc/cve-scan-api/scanner.env — ustaw NVD_API_KEY i CVE_API_TOKEN

# Systemd
sudo cp dotfiles/scanner.service /etc/systemd/system/cve-scan-api.service
sudo systemctl daemon-reload
sudo systemctl enable --now cve-scan-api

# Nginx
sudo cp dotfiles/scanner_nginx.conf /etc/nginx/sites-available/cve-scan-api
sudo ln -s /etc/nginx/sites-available/cve-scan-api /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

```bash
# Zarządzanie serwisem
sudo systemctl status cve-scan-api
sudo systemctl restart cve-scan-api
journalctl -u cve-scan-api -f
```

## Test

```bash
# Health check (bezpośrednio do backendu — tylko z serwera)
curl -s http://127.0.0.1:8088/health

# Skanowanie przez nginx (HTTPS — TLS terminowany przez nginx)
curl -s -X POST https://scanner.local/scan \
  -H 'Content-Type: application/json' \
  -H 'X-API-Token: twój-token' \
  -d '{
    "host": "192.168.1.10",
    "user": "admin",
    "password": "hasło",
    "suite": "trixie",
    "vuln_score": 7.0,
    "show_unscored": false
  }'
```

```powershell
# PowerShell
$body = @{
    host         = "192.168.1.10"
    user         = "admin"
    password     = "hasło"
    suite        = "trixie"
    vuln_score   = 7.0
    show_unscored = $false
} | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri "https://scanner.local/scan" `
    -ContentType "application/json" `
    -Headers @{"X-API-Token" = "twój-token"} `
    -Body $body | ConvertTo-Json -Depth 10
```

## Bezpieczeństwo

- Hasło SSH jest przesyłane w body JSON — **wymagane** TLS (nginx + certbot).
- Włącz `CVE_API_TOKEN` w produkcji.
- Ogranicz dostęp do API firewallem (tylko zaufane hosty).
- Docelowo: klucze SSH zamiast haseł (`ScanRequest.password` do usunięcia).
- Parametr `suite` jest walidowany względem listy dozwolonych wydań.
- Token API jest porównywany przez `hmac.compare_digest` (odporność na timing attack).

## Troubleshooting

| Problem | Rozwiązanie |
|---------|-------------|
| `401 Unauthorized` | Nieprawidłowy lub brakujący `X-API-Token` (sprawdź `CVE_API_TOKEN`) |
| `500` przy skanowaniu | `journalctl -u cve-scan-api -f` — szukaj `Unhandled error` |
| Puste `vulnerabilities` | Sprawdź czy `debsecan` działa na hoście: `ssh user@host debsecan --suite trixie` |
| `sshpass: command not found` | `apt install sshpass` na serwerze API |
| `DebsecanError: Niedozwolona suite` | Podaj jedną z: `trixie`, `bookworm`, `bullseye`, `buster`, `sid` … |
| Cache nie zapisuje się | Sprawdź `CVE_CACHE_PATH` i uprawnienia do katalogu `/var/cache/cve-scan-api/` |
