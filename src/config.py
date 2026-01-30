import os

DEFAULT_BASE_URL = "https://solodit.cyfrin.io/api/v1/solodit"
DEFAULT_CACHE_PATH = os.path.expanduser("~/.cache/solodit_cache.sqlite")
DEFAULT_FINDINGS_DB_PATH = os.path.expanduser("~/.cache/solodit_findings.sqlite")
DEFAULT_CACHE_TTL_DAYS = 30


def get_base_url() -> str:
    return os.environ.get("SOLODIT_BASE_URL", DEFAULT_BASE_URL).rstrip("/")


def get_cache_path() -> str:
    return os.environ.get("SOLODIT_CACHE_PATH", DEFAULT_CACHE_PATH)


def get_findings_db_path() -> str:
    return os.environ.get("SOLODIT_FINDINGS_DB_PATH", DEFAULT_FINDINGS_DB_PATH)


def get_cache_ttl_days() -> int:
    raw = os.environ.get("SOLODIT_CACHE_TTL_DAYS", str(DEFAULT_CACHE_TTL_DAYS))
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_CACHE_TTL_DAYS


def get_api_key() -> str:
    return os.environ.get("SOLODIT_API_KEY", "")
