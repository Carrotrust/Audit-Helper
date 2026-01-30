import json
import sqlite3
import time
from typing import Iterable, List, Optional

from .client import SoloditClient
from .config import get_findings_db_path


class SoloditFindingsIndex:
    def __init__(self, path: Optional[str] = None) -> None:
        self.path = path or get_findings_db_path()
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts
                USING fts5(
                    title,
                    description,
                    tags,
                    impact UNINDEXED,
                    quality_score UNINDEXED,
                    source_link UNINDEXED,
                    firm_name UNINDEXED,
                    external_id UNINDEXED,
                    raw_json UNINDEXED
                )
                """
            )

    def get_meta(self, key: str) -> Optional[str]:
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
                (key, value),
            )

    def upsert_findings(self, findings: Iterable[dict]) -> None:
        with sqlite3.connect(self.path) as conn:
            for finding in findings:
                external_id = finding.get("id") or finding.get("finding_id") or ""
                title = finding.get("title") or ""
                description = finding.get("description") or finding.get("summary") or ""
                tags = finding.get("tags") or finding.get("keywords") or ""
                if isinstance(tags, list):
                    tags = " ".join([str(t) for t in tags])
                impact = finding.get("impact") or ""
                quality = finding.get("quality_score") or finding.get("qualityScore") or ""
                source_link = finding.get("source_link") or finding.get("sourceLink") or ""
                firm = finding.get("firm_name") or finding.get("firmName") or ""

                if external_id:
                    conn.execute(
                        "DELETE FROM findings_fts WHERE external_id = ?",
                        (external_id,),
                    )

                conn.execute(
                    """
                    INSERT INTO findings_fts(
                        title,
                        description,
                        tags,
                        impact,
                        quality_score,
                        source_link,
                        firm_name,
                        external_id,
                        raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        title,
                        description,
                        tags,
                        impact,
                        str(quality),
                        source_link,
                        firm,
                        external_id,
                        json.dumps(finding),
                    ),
                )

    def search(
        self,
        query: str,
        *,
        impact: Optional[List[str]] = None,
        min_quality: Optional[int] = None,
        limit: int = 20,
    ) -> List[dict]:
        where = []
        params: List[str] = [query]
        if impact:
            placeholders = ",".join("?" for _ in impact)
            where.append(f"impact IN ({placeholders})")
            params.extend(impact)
        if min_quality is not None:
            where.append("CAST(quality_score AS INTEGER) >= ?")
            params.append(str(min_quality))
        where_sql = f"AND {' AND '.join(where)}" if where else ""

        sql = f"""
            SELECT
                title, impact, quality_score, source_link, firm_name, raw_json
            FROM findings_fts
            WHERE findings_fts MATCH ?
            {where_sql}
            ORDER BY bm25(findings_fts)
            LIMIT ?
        """
        params.append(str(limit))
        with sqlite3.connect(self.path) as conn:
            rows = conn.execute(sql, params).fetchall()
        results = []
        for title, impact_val, quality, link, firm, raw_json in rows:
            try:
                raw = json.loads(raw_json)
            except json.JSONDecodeError:
                raw = {}
            if not raw:
                raw = {
                    "title": title,
                    "impact": impact_val,
                    "quality_score": quality,
                    "source_link": link,
                    "firm_name": firm,
                }
            results.append(raw)
        return results


def sync_findings(
    *,
    client: Optional[SoloditClient] = None,
    page_size: int = 100,
    max_pages: Optional[int] = None,
    sleep_seconds: float = 0.2,
    index: Optional[SoloditFindingsIndex] = None,
    start_page: int = 1,
    resume: bool = False,
) -> int:
    client = client or SoloditClient()
    index = index or SoloditFindingsIndex()

    if resume:
        last_page = index.get_meta("last_synced_page")
        if last_page and last_page.isdigit():
            start_page = max(start_page, int(last_page) + 1)

    total = 0
    page = start_page
    total_results = None
    while True:
        payload = client.findings(
            filters={},
            page=page,
            page_size=page_size,
        )
        findings = payload.get("findings", []) or []
        index.upsert_findings(findings)
        total += len(findings)
        index.set_meta("last_synced_page", str(page))

        metadata = payload.get("metadata", {}) or {}
        if total_results is None:
            total_results = metadata.get("totalResults")

        if not findings:
            break
        if max_pages is not None and page >= max_pages:
            break
        if total_results is not None and total >= int(total_results):
            break
        page += 1
        time.sleep(sleep_seconds)

    return total
