# -*- coding: utf-8 -*-

# --- ENV names ---
# https://nvd.nist.gov/developers/request-an-api-key
ENV_NVD_API_KEY = "913D48DA-F0E3-F011-8366-0EBF96DE670D"
# optional api token for http server
ENV_CVE_API_TOKEN = "CVE_API_TOKEN"

ENV_LOG_LEVEL = "CVE_LOG_LEVEL"            # DEBUG/INFO/WARNING/ERROR
ENV_LOG_JSON = "CVE_LOG_JSON"              # "1"/"0"
ENV_LOG_REQUEST_ID = "CVE_LOG_REQUEST_ID"  # "1"/"0"

ENV_CACHE_ENABLED = "CVE_CACHE_ENABLED"    # "1"/"0"
ENV_CACHE_PATH = "CVE_CACHE_PATH"          # np. /var/cache/cve-api/nvd_cache.json
ENV_CACHE_TTL = "CVE_CACHE_TTL"            # sekundy

ENV_HTTP_TIMEOUT = "CVE_HTTP_TIMEOUT"      # sekundy
ENV_NVD_BASE_URL = "CVE_NVD_BASE_URL"      # override

ENV_LISTEN = "CVE_LISTEN"
ENV_PORT = "CVE_PORT"
ENV_MAX_BODY = "CVE_MAX_BODY"

# --- Defaults ---
DEFAULT_LISTEN = "127.0.0.1"
DEFAULT_PORT = 8088
DEFAULT_MAX_BODY_BYTES = 1024 * 1024  # 1 MiB

DEFAULT_SUITE = "trixie"
DEFAULT_HTTP_TIMEOUT_SECONDS = 15

DEFAULT_CACHE_ENABLED = True
DEFAULT_CACHE_FILENAME = "nvd_cache.json"
DEFAULT_CACHE_TTL_SECONDS = 24 * 60 * 60  # 24h

DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_JSON = False
DEFAULT_LOG_REQUEST_ID = True

# --- API paths ---
PATH_HEALTH = "/health"
PATH_SCAN = "/scan"

# --- NVD ---
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
