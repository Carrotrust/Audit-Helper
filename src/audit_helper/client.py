import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional

from .cache import SoloditCache
from .config import get_api_key, get_base_url


class SoloditClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        cache: Optional[SoloditCache] = None,
    ) -> None:
        self.base_url = (base_url or get_base_url()).rstrip("/")
        self.api_key = api_key or get_api_key()
        self.cache = cache or SoloditCache()

    def _build_url(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        path = path if path.startswith("/") else f"/{path}"
        url = f"{self.base_url}{path}"
        if params:
            query = urllib.parse.urlencode(params, doseq=True)
            url = f"{url}?{query}"
        return url

    def request(
        self,
        path: str,
        *,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Dict[str, Any]] = None,
        use_cache: bool = True,
        max_retries: int = 5,
        backoff_seconds: float = 5.0,
    ) -> Any:
        url = self._build_url(path, params)
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-Cyfrin-API-Key"] = self.api_key

        cache_key = self.cache.make_key(method, url, params, body)
        if use_cache:
            cached = self.cache.get(cache_key)
            if cached is not None:
                return cached.payload

        data = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read().decode("utf-8")
                    payload = json.loads(raw) if raw else {}
                break
            except urllib.error.HTTPError as exc:
                raw = exc.read().decode("utf-8")
                if exc.code == 429 and attempt < max_retries:
                    retry_after = exc.headers.get("Retry-After")
                    reset_at = exc.headers.get("X-RateLimit-Reset")
                    sleep_for = None
                    if retry_after and retry_after.isdigit():
                        sleep_for = int(retry_after)
                    elif reset_at and reset_at.isdigit():
                        reset_ts = int(reset_at)
                        sleep_for = max(0, reset_ts - int(time.time())) + 1
                    else:
                        sleep_for = backoff_seconds * (2**attempt)
                    time.sleep(sleep_for)
                    attempt += 1
                    continue
                raise RuntimeError(f"Solodit API error {exc.code}: {raw}") from exc
            except urllib.error.URLError as exc:
                raise RuntimeError(f"Solodit API connection error: {exc}") from exc

        if use_cache:
            self.cache.set(cache_key, payload)
        return payload

    def search(self, query: str, *, path: str = "/search") -> Any:
        return self.request(path, params={"q": query})

    def findings(
        self,
        *,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 50,
        path: str = "/findings",
    ) -> Any:
        body = {
            "page": page,
            "pageSize": page_size,
            "filters": filters or {},
        }
        return self.request(path, method="POST", body=body)
