import argparse
import os
import json
from typing import Dict, List, Optional

from cache import SoloditCache
from audit import (
    aggregate_unique_findings,
    scan_findings,
    scan_local_index,
    scan_local_index_files,
    scan_local_index_per_function,
    scan_local_index_per_function_files,
)
from client import SoloditClient
from index import sync_findings


def _parse_params(items: Optional[List[str]]) -> Dict[str, str]:
    params: Dict[str, str] = {}
    if not items:
        return params
    for item in items:
        if "=" not in item:
            raise SystemExit(f"Invalid param '{item}'. Expected key=value.")
        key, value = item.split("=", 1)
        params[key] = value
    return params


def _print_json(payload) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _cmd_search(args: argparse.Namespace) -> None:
    client = SoloditClient()
    payload = client.search(args.query, path=args.path)
    _print_json(payload)


def _cmd_request(args: argparse.Namespace) -> None:
    client = SoloditClient()
    params = _parse_params(args.params)
    body = _parse_params(args.body) if args.body else None
    payload = client.request(
        args.path,
        method=args.method,
        params=params or None,
        body=body,
        use_cache=not args.no_cache,
    )
    _print_json(payload)


def _cmd_cache_clear(_: argparse.Namespace) -> None:
    cache = SoloditCache()
    cache.clear()
    print("Cache cleared.")


def _cmd_findings(args: argparse.Namespace) -> None:
    client = SoloditClient()
    filters = json.loads(args.filters_json) if args.filters_json else None
    payload = client.findings(
        filters=filters,
        page=args.page,
        page_size=args.page_size,
        path=args.path,
    )
    _print_json(payload)


def _render_report(payload: dict, top: int) -> str:
    findings = payload.get("findings", []) or []
    meta = payload.get("metadata", {}) or {}
    rate = payload.get("rateLimit", {}) or {}
    lines = []
    lines.append(f"Findings: {meta.get('totalResults', 'unknown')} total")
    if rate:
        lines.append(f"Rate limit: {rate.get('remaining', '?')}/{rate.get('limit', '?')}")
    if not findings:
        return "\n".join(lines) + "\n"
    lines.append("")
    for idx, finding in enumerate(findings[:top], start=1):
        title = finding.get("title", "Untitled")
        impact = finding.get("impact", "UNKNOWN")
        firm = finding.get("firm_name", "Unknown")
        quality = finding.get("quality_score", "?")
        link = finding.get("source_link", "")
        lines.append(f"{idx}. [{impact}] {title}")
        lines.append(f"   Firm: {firm} | Quality: {quality}/5")
        if link:
            lines.append(f"   Link: {link}")
    return "\n".join(lines) + "\n"


def _render_function_report(results: List[dict], top: int) -> str:
    printed = 0
    lines: List[str] = []
    for entry in results:
        findings = entry.get("findings", []) or []
        if not findings:
            continue
        lines.append(f"Function: {entry.get('function')} ({entry.get('file')})")
        for idx, finding in enumerate(findings[:top], start=1):
            title = finding.get("title", "Untitled")
            impact = finding.get("impact", "UNKNOWN")
            firm = finding.get("firm_name", "Unknown")
            quality = finding.get("quality_score", "?")
            link = finding.get("source_link", "")
            lines.append(f"  {idx}. [{impact}] {title}")
            lines.append(f"     Firm: {firm} | Quality: {quality}/5")
            if link:
                lines.append(f"     Link: {link}")
        lines.append("")
        printed += 1
        if printed >= 10:
            break
    return "\n".join(lines) + ("\n" if lines else "")


def _render_unique_report(results: List[dict]) -> str:
    lines: List[str] = []
    for idx, entry in enumerate(results, start=1):
        finding = entry.get("finding", {}) or {}
        title = finding.get("title", "Untitled")
        impact = finding.get("impact", "UNKNOWN")
        firm = finding.get("firm_name", "Unknown")
        quality = finding.get("quality_score", "?")
        link = finding.get("source_link", "")
        lines.append(f"{idx}. [{impact}] {title}")
        lines.append(f"   Firm: {firm} | Quality: {quality}/5")
        if link:
            lines.append(f"   Link: {link}")
        matches = entry.get("matches", []) or []
        if matches:
            for m in matches:
                lines.append(f"   Match: {m.get('file')}::{m.get('function')}")
        lines.append("")
    return "\n".join(lines) + ("\n" if lines else "")


def _cmd_scan(args: argparse.Namespace) -> None:
    if args.api:
        query, payload = scan_findings(
            args.path,
            extra_keywords=args.keyword,
            impact=args.impact,
            quality_score=args.quality_score,
            sort_field=args.sort_field,
            sort_direction=args.sort_direction,
            page=args.page,
            page_size=args.page_size,
        )
        print(json.dumps({"sources": query.sources, "keywords": query.keywords}, indent=2))
        if args.raw:
            output = json.dumps(payload, indent=2, sort_keys=True)
        else:
            output = _render_report(payload, top=args.top)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(output)
        else:
            print(output, end="")
        return

    if args.per_function or args.unique_findings:
        if args.file_list:
            with open(args.file_list, "r", encoding="utf-8") as fh:
                files = [line.strip() for line in fh if line.strip()]
            files = [
                f if os.path.isabs(f) else os.path.normpath(os.path.join(args.path, f))
                for f in files
            ]
            per_func_limit = 1 if args.unique_findings else args.top
            query, func_results = scan_local_index_per_function_files(
                files,
                extra_keywords=args.keyword,
                impact=args.impact,
                quality_score=args.quality_score,
                per_function_limit=per_func_limit,
                include_base=not args.strict,
                min_overlap=args.min_overlap,
                min_code_similarity=args.min_code_similarity,
                require_snippet=args.require_snippet,
                min_core_overlap=args.min_core_overlap,
            )
        else:
            per_func_limit = 1 if args.unique_findings else args.top
            query, func_results = scan_local_index_per_function(
                args.path,
                extra_keywords=args.keyword,
                impact=args.impact,
                quality_score=args.quality_score,
                limit=per_func_limit,
                include_base=not args.strict,
                min_overlap=args.min_overlap,
                min_code_similarity=args.min_code_similarity,
                require_snippet=args.require_snippet,
                min_core_overlap=args.min_core_overlap,
            )
        print(json.dumps({"sources": query.sources, "keywords": query.keywords}, indent=2))
        if args.raw:
            output = json.dumps({"results": func_results}, indent=2, sort_keys=True)
        else:
            if args.unique_findings:
                unique = aggregate_unique_findings(
                    func_results,
                    max_findings=args.unique_findings,
                    max_functions_per_finding=3,
                )
                output = _render_unique_report(unique)
            else:
                output = _render_function_report(func_results, top=args.top)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(output)
        else:
            print(output, end="")
        return

    if args.file_list:
        with open(args.file_list, "r", encoding="utf-8") as fh:
            files = [line.strip() for line in fh if line.strip()]
        files = [
            f if os.path.isabs(f) else os.path.normpath(os.path.join(args.path, f))
            for f in files
        ]
        query, results = scan_local_index_files(
            files,
            extra_keywords=args.keyword,
            impact=args.impact,
            quality_score=args.quality_score,
            limit=args.top,
        )
    else:
        query, results = scan_local_index(
            args.path,
            extra_keywords=args.keyword,
            impact=args.impact,
            quality_score=args.quality_score,
            limit=args.top,
        )
    print(json.dumps({"sources": query.sources, "keywords": query.keywords}, indent=2))
    payload = {"findings": results, "metadata": {"totalResults": len(results)}}
    if args.raw:
        output = json.dumps(payload, indent=2, sort_keys=True)
    else:
        output = _render_report(payload, top=args.top)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(output)
    else:
        print(output, end="")


def _cmd_sync(args: argparse.Namespace) -> None:
    if args.page_size > 100:
        raise SystemExit("page-size must be <= 100 for the Solodit API")
    count = sync_findings(
        page_size=args.page_size,
        max_pages=args.max_pages,
        sleep_seconds=args.sleep_seconds,
        start_page=args.start_page,
        resume=args.resume,
    )
    print(f"Synced {count} findings into the local index.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Solodit API CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    search = sub.add_parser("search", help="Search Solodit by query")
    search.add_argument("query", help="Search query string")
    search.add_argument("--path", default="/search", help="Endpoint path (default: /search)")
    search.set_defaults(func=_cmd_search)

    request = sub.add_parser("request", help="Call a custom Solodit API endpoint")
    request.add_argument("--path", required=True, help="Endpoint path, e.g. /reports")
    request.add_argument("--method", default="GET", help="HTTP method (default: GET)")
    request.add_argument(
        "--params",
        action="append",
        help="Query parameter in key=value form (repeatable)",
    )
    request.add_argument(
        "--body",
        action="append",
        help="JSON body field in key=value form (repeatable)",
    )
    request.add_argument("--no-cache", action="store_true", help="Disable cache")
    request.set_defaults(func=_cmd_request)

    findings = sub.add_parser("findings", help="Search Solodit findings")
    findings.add_argument("--path", default="/findings", help="Endpoint path (default: /findings)")
    findings.add_argument("--page", type=int, default=1, help="Page number (default: 1)")
    findings.add_argument("--page-size", type=int, default=50, help="Page size (default: 50)")
    findings.add_argument(
        "--filters-json",
        help="Filters as JSON string, e.g. '{\"impact\":[\"HIGH\"],\"keywords\":\"oracle\"}'",
    )
    findings.set_defaults(func=_cmd_findings)

    scan = sub.add_parser("scan", help="Scan a file or folder and query Solodit")
    scan.add_argument("path", help="File or folder to scan")
    scan.add_argument(
        "--keyword",
        action="append",
        help="Extra keyword to include (repeatable)",
    )
    scan.add_argument("--impact", action="append", help="Impact filter (repeatable)")
    scan.add_argument("--quality-score", type=int, help="Minimum quality score")
    scan.add_argument("--sort-field", default="Quality", help="Sort field (default: Quality)")
    scan.add_argument("--sort-direction", default="Desc", help="Sort direction (default: Desc)")
    scan.add_argument("--page", type=int, default=1, help="Page number (default: 1)")
    scan.add_argument("--page-size", type=int, default=20, help="Page size (default: 20)")
    scan.add_argument("--top", type=int, default=5, help="Top findings to print (default: 5)")
    scan.add_argument("--raw", action="store_true", help="Print raw JSON instead of report")
    scan.add_argument("--api", action="store_true", help="Query the API directly instead of the local index")
    scan.add_argument("--per-function", action="store_true", help="Match findings per Solidity function")
    scan.add_argument("--out", help="Write report to a file instead of stdout")
    scan.add_argument("--file-list", help="Path to a newline-delimited file list")
    scan.add_argument(
        "--unique-findings",
        type=int,
        help="Aggregate and print unique findings across functions (e.g. 20)",
    )
    scan.add_argument(
        "--strict",
        action="store_true",
        help="Use only function-local keywords (no global base keywords)",
    )
    scan.add_argument(
        "--min-overlap",
        type=int,
        default=5,
        help="Minimum keyword overlap between function and finding text (default: 5)",
    )
    scan.add_argument(
        "--min-code-similarity",
        type=float,
        default=0.0,
        help="Minimum code snippet similarity (Jaccard on token 3-grams)",
    )
    scan.add_argument(
        "--require-snippet",
        action="store_true",
        help="Only keep findings with embedded code snippets",
    )
    scan.add_argument(
        "--min-core-overlap",
        type=int,
        default=2,
        help="Minimum overlap on core security terms (default: 2)",
    )
    scan.set_defaults(func=_cmd_scan)

    sync = sub.add_parser("sync", help="Sync findings into the local index")
    sync.add_argument("--page-size", type=int, default=100, help="Page size (default: 100)")
    sync.add_argument("--max-pages", type=int, help="Maximum pages to fetch")
    sync.add_argument("--sleep-seconds", type=float, default=0.2, help="Delay between requests")
    sync.add_argument("--start-page", type=int, default=1, help="Start page (default: 1)")
    sync.add_argument("--resume", action="store_true", help="Resume from last synced page")
    sync.set_defaults(func=_cmd_sync)

    cache_clear = sub.add_parser("cache-clear", help="Clear the local cache")
    cache_clear.set_defaults(func=_cmd_cache_clear)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
