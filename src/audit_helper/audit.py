import os
import re
from collections import Counter
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from .client import SoloditClient
from .index import SoloditFindingsIndex


SOLIDITY_KEYWORDS = {
    "address",
    "bool",
    "bytes",
    "byte",
    "contract",
    "event",
    "enum",
    "error",
    "external",
    "fallback",
    "function",
    "internal",
    "mapping",
    "memory",
    "modifier",
    "payable",
    "pragma",
    "public",
    "private",
    "returns",
    "revert",
    "require",
    "struct",
    "string",
    "unchecked",
    "using",
    "view",
    "pure",
}

STOPWORDS = {
    "the",
    "and",
    "for",
    "with",
    "from",
    "this",
    "that",
    "then",
    "else",
    "true",
    "false",
    "uint",
    "uint256",
    "int",
    "int256",
    "bytes32",
    "bytes4",
    "bytes20",
    "address",
    "return",
}

VULN_TERMS = [
    "reentrancy",
    "reentrant",
    "oracle",
    "price",
    "flashloan",
    "flash",
    "front",
    "sandwich",
    "slippage",
    "overflow",
    "underflow",
    "rounding",
    "precision",
    "access",
    "auth",
    "owner",
    "onlyowner",
    "delegatecall",
    "call",
    "staticcall",
    "create2",
    "selfdestruct",
    "txorigin",
    "permit",
    "signature",
    "nonce",
    "upgrade",
    "proxy",
    "initializer",
    "pause",
    "unpause",
    "timelock",
    "grief",
    "dos",
    "gas",
    "block",
    "timestamp",
    "chainid",
]

DOMAIN_TERMS = [
    "bridge",
    "bridged",
    "messenger",
    "wormhole",
    "relayer",
    "optimism",
    "arbitrum",
    "gnosis",
    "polygon",
    "l2",
    "oracle",
    "price",
    "uniswap",
    "balancer",
    "amm",
    "liquidity",
    "tokenomics",
    "staking",
    "reward",
    "emission",
    "governor",
    "governance",
    "timelock",
    "proposal",
    "vote",
    "multisig",
    "safe",
    "guard",
    "proxy",
    "upgrade",
    "initializer",
    "burn",
    "buyback",
    "dispenser",
    "registry",
    "service",
    "verification",
    "checkpoint",
]

CORE_SECURITY_TERMS = [
    "reentrancy",
    "delegatecall",
    "call",
    "staticcall",
    "oracle",
    "price",
    "timelock",
    "upgrade",
    "proxy",
    "signature",
    "nonce",
    "permit",
    "access",
    "auth",
    "ownership",
    "bridge",
    "cross-chain",
    "dos",
    "grief",
    "front-run",
    "frontrun",
    "flashloan",
    "slippage",
]

BASE_KEYWORDS = [
    "bridge",
    "oracle",
    "timelock",
    "proxy",
    "upgrade",
    "multisig",
    "governance",
    "reentrancy",
    "delegatecall",
    "access control",
    "price",
    "cross-chain",
]

EXTENSIONS = {".sol", ".vy", ".rs", ".go", ".py", ".js", ".ts"}


@dataclass
class AuditQuery:
    keywords: List[str]
    sources: List[str]


def _read_text(path: str, max_bytes: int = 500_000) -> str:
    with open(path, "rb") as fh:
        data = fh.read(max_bytes)
    return data.decode("utf-8", errors="ignore")


def _iter_files(path: str) -> Iterable[str]:
    if os.path.isfile(path):
        yield path
        return
    for root, _, files in os.walk(path):
        for name in files:
            ext = os.path.splitext(name)[1].lower()
            if ext in EXTENSIONS:
                yield os.path.join(root, name)


def _tokenize(text: str) -> List[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", text)


def _extract_identifiers(text: str) -> List[str]:
    patterns = [
        r"\bcontract\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"\binterface\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"\blibrary\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)",
        r"\bmodifier\s+([A-Za-z_][A-Za-z0-9_]*)",
    ]
    results: List[str] = []
    for pat in patterns:
        results.extend(re.findall(pat, text))
    return results


def _extract_solidity_functions(text: str) -> List[Tuple[str, str]]:
    # Naive parser: finds "function name(...)" and captures balanced braces.
    functions: List[Tuple[str, str]] = []
    for match in re.finditer(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", text):
        name = match.group(1)
        brace_idx = text.find("{", match.end())
        if brace_idx == -1:
            continue
        depth = 0
        end_idx = None
        for i in range(brace_idx, len(text)):
            ch = text[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end_idx = i + 1
                    break
        if end_idx:
            body = text[brace_idx:end_idx]
            functions.append((name, body))
    return functions


def _extract_keywords(paths: Sequence[str], extra_keywords: Optional[Sequence[str]] = None) -> AuditQuery:
    counts: Counter = Counter()
    sources: List[str] = []
    for path in paths:
        try:
            text = _read_text(path)
        except (OSError, UnicodeDecodeError):
            continue
        sources.append(path)
        tokens = [t.lower() for t in _tokenize(text)]
        identifiers = [i.lower() for i in _extract_identifiers(text)]
        for token in tokens:
            if token in STOPWORDS or token in SOLIDITY_KEYWORDS:
                continue
            counts[token] += 1
        for ident in identifiers:
            counts[ident] += 2
        # boost known vuln terms present in text
        lowered = text.lower()
        for term in VULN_TERMS:
            if term in lowered:
                counts[term] += 3
        for term in DOMAIN_TERMS:
            if term in lowered:
                counts[term] += 2

    for kw in BASE_KEYWORDS:
        counts[kw.lower()] += 4

    if extra_keywords:
        for kw in extra_keywords:
            counts[kw.lower()] += 5

    # prefer longer, more frequent terms
    ranked = sorted(
        counts.items(),
        key=lambda kv: (kv[1], len(kv[0])),
        reverse=True,
    )
    keywords = [k for k, _ in ranked[:20]]
    for kw in BASE_KEYWORDS:
        kw = kw.lower()
        if kw not in keywords:
            keywords.append(kw)
    return AuditQuery(keywords=keywords, sources=sources)


def _extract_keywords_from_text(
    text: str,
    *,
    extra_keywords: Optional[Sequence[str]] = None,
    include_base: bool = True,
) -> List[str]:
    counts: Counter = Counter()
    tokens = [t.lower() for t in _tokenize(text)]
    for token in tokens:
        if token in STOPWORDS or token in SOLIDITY_KEYWORDS:
            continue
        counts[token] += 1
    lowered = text.lower()
    for term in VULN_TERMS:
        if term in lowered:
            counts[term] += 3
    for term in DOMAIN_TERMS:
        if term in lowered:
            counts[term] += 2

    if include_base:
        for kw in BASE_KEYWORDS:
            counts[kw.lower()] += 4
    if extra_keywords:
        for kw in extra_keywords:
            counts[kw.lower()] += 5

    ranked = sorted(
        counts.items(),
        key=lambda kv: (kv[1], len(kv[0])),
        reverse=True,
    )
    keywords = [k for k, _ in ranked[:20]]
    if include_base:
        for kw in BASE_KEYWORDS:
            kw = kw.lower()
            if kw not in keywords:
                keywords.append(kw)
    return keywords


def build_query(path: str, extra_keywords: Optional[Sequence[str]] = None) -> AuditQuery:
    files = list(_iter_files(path))
    if not files:
        return AuditQuery(keywords=list(extra_keywords or []), sources=[])
    return _extract_keywords(files, extra_keywords=extra_keywords)


def scan_findings(
    path: str,
    *,
    extra_keywords: Optional[Sequence[str]] = None,
    impact: Optional[List[str]] = None,
    quality_score: Optional[int] = None,
    sort_field: str = "Quality",
    sort_direction: str = "Desc",
    page: int = 1,
    page_size: int = 20,
) -> Tuple[AuditQuery, dict]:
    query = build_query(path, extra_keywords=extra_keywords)
    filters = {
        "keywords": " ".join(query.keywords),
        "sortField": sort_field,
        "sortDirection": sort_direction,
    }
    if impact:
        filters["impact"] = impact
    if quality_score is not None:
        filters["qualityScore"] = quality_score

    client = SoloditClient()
    payload = client.findings(
        filters=filters,
        page=page,
        page_size=page_size,
    )
    return query, payload


def _build_fts_query(keywords: Sequence[str]) -> str:
    parts: List[str] = []
    for kw in keywords:
        kw = kw.strip()
        if not kw:
            continue
        if re.search(r"[^A-Za-z0-9_]", kw):
            parts.append(f"\"{kw}\"")
        else:
            parts.append(kw)
    return " OR ".join(parts) if parts else ""


def _finding_text(finding: dict) -> str:
    parts = [
        str(finding.get("title") or ""),
        str(finding.get("description") or ""),
        str(finding.get("summary") or ""),
        str(finding.get("tags") or ""),
        str(finding.get("keywords") or ""),
    ]
    return " ".join(parts).lower()


def _keyword_overlap(finding: dict, keywords: Sequence[str]) -> int:
    text = _finding_text(finding)
    if not text:
        return 0
    count = 0
    for kw in keywords:
        kw = kw.lower()
        if not kw:
            continue
        if kw in text:
            count += 1
    return count


def _core_overlap(finding: dict, func_text: str, min_core: int) -> bool:
    if min_core <= 0:
        return True
    finding_text = _finding_text(finding)
    func_text = func_text.lower()
    count = 0
    for term in CORE_SECURITY_TERMS:
        if term in finding_text and term in func_text:
            count += 1
            if count >= min_core:
                return True
    return False


def _extract_code_snippets(finding: dict) -> List[str]:
    snippets: List[str] = []
    # common fields
    for key in ("content", "code", "snippet", "snippets", "poc", "details", "description", "summary", "analysis"):
        val = finding.get(key)
        if not val:
            continue
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    snippets.extend(_extract_code_blocks(item))
        elif isinstance(val, str):
            snippets.extend(_extract_code_blocks(val))
    return [s for s in snippets if s.strip()]


def _extract_code_blocks(text: str) -> List[str]:
    blocks = re.findall(r"```(?:[a-zA-Z0-9_-]+)?\\n(.*?)```", text, flags=re.DOTALL)
    return [b.strip() for b in blocks if b.strip()]


def _normalize_code(text: str) -> str:
    # Strip comments
    text = re.sub(r"//.*?$", "", text, flags=re.MULTILINE)
    text = re.sub(r"/\\*.*?\\*/", "", text, flags=re.DOTALL)
    # Normalize addresses and hex literals
    text = re.sub(r"0x[a-fA-F0-9]+", "0xHEX", text)
    # Normalize numbers
    text = re.sub(r"\\b\\d+\\b", "NUM", text)
    return text


def _code_tokens(text: str) -> List[str]:
    text = _normalize_code(text)
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*|0xHEX|NUM|==|!=|<=|>=|&&|\\|\\||[{}();.,=<>+\\-*/%]", text)
    # Normalize identifiers to reduce sensitivity to variable names
    normalized = []
    for t in tokens:
        if re.match(r"[A-Za-z_][A-Za-z0-9_]*", t) and t not in {
            "if","else","for","while","return","require","revert","assert","emit","function","constructor",
            "mapping","struct","event","error","modifier","public","private","internal","external","view","pure",
            "memory","calldata","storage","payable","unchecked","try","catch","new"
        }:
            normalized.append("ID")
        else:
            normalized.append(t)
    return normalized


def _token_ngrams(tokens: List[str], n: int = 1) -> List[str]:
    if len(tokens) < n:
        return []
    return [" ".join(tokens[i:i + n]) for i in range(len(tokens) - n + 1)]


def _code_similarity(a: str, b: str) -> float:
    ta = _code_tokens(a)
    tb = _code_tokens(b)
    ga = set(_token_ngrams(ta, 3))
    gb = set(_token_ngrams(tb, 3))
    if not ga or not gb:
        return 0.0
    inter = len(ga & gb)
    union = len(ga | gb)
    return inter / union if union else 0.0


def scan_local_index(
    path: str,
    *,
    extra_keywords: Optional[Sequence[str]] = None,
    impact: Optional[List[str]] = None,
    quality_score: Optional[int] = None,
    limit: int = 20,
) -> Tuple[AuditQuery, List[dict]]:
    query = build_query(path, extra_keywords=extra_keywords)
    fts_query = _build_fts_query(query.keywords)
    index = SoloditFindingsIndex()
    results = index.search(
        fts_query,
        impact=impact,
        min_quality=quality_score,
        limit=limit,
    )
    return query, results


def scan_local_index_files(
    files: Sequence[str],
    *,
    extra_keywords: Optional[Sequence[str]] = None,
    impact: Optional[List[str]] = None,
    quality_score: Optional[int] = None,
    limit: int = 20,
) -> Tuple[AuditQuery, List[dict]]:
    query = _extract_keywords(list(files), extra_keywords=extra_keywords)
    fts_query = _build_fts_query(query.keywords)
    index = SoloditFindingsIndex()
    results = index.search(
        fts_query,
        impact=impact,
        min_quality=quality_score,
        limit=limit,
    )
    return AuditQuery(keywords=query.keywords, sources=list(files)), results


def scan_local_index_per_function(
    path: str,
    *,
    extra_keywords: Optional[Sequence[str]] = None,
    impact: Optional[List[str]] = None,
    quality_score: Optional[int] = None,
    limit: int = 5,
    include_base: bool = True,
    min_overlap: int = 0,
    min_code_similarity: float = 0.0,
    require_snippet: bool = False,
    min_core_overlap: int = 0,
) -> Tuple[AuditQuery, List[dict]]:
    query = build_query(path, extra_keywords=extra_keywords)
    index = SoloditFindingsIndex()

    findings_by_function: List[dict] = []
    for file_path in query.sources:
        if not file_path.endswith(".sol"):
            continue
        try:
            text = _read_text(file_path)
        except (OSError, UnicodeDecodeError):
            continue
        for func_name, body in _extract_solidity_functions(text):
            func_keywords = _extract_keywords_from_text(
                body,
                extra_keywords=[func_name],
                include_base=include_base,
            )
            fts_query = _build_fts_query(func_keywords)
            results = index.search(
                fts_query,
                impact=impact,
                min_quality=quality_score,
                limit=limit,
            )
            if min_overlap > 0:
                results = [r for r in results if _keyword_overlap(r, func_keywords) >= min_overlap]
            if min_code_similarity > 0 or require_snippet:
                filtered = []
                for r in results:
                    snippets = _extract_code_snippets(r)
                    if require_snippet and not snippets:
                        continue
                    best = 0.0
                    for snip in snippets:
                        best = max(best, _code_similarity(body, snip))
                    if best >= min_code_similarity:
                        filtered.append(r)
                results = filtered
            if min_core_overlap > 0:
                results = [r for r in results if _core_overlap(r, body, min_core_overlap)]
            findings_by_function.append(
                {
                    "file": file_path,
                    "function": func_name,
                    "keywords": func_keywords,
                    "findings": results,
                }
            )

    return query, findings_by_function


def scan_local_index_per_function_files(
    files: Sequence[str],
    *,
    extra_keywords: Optional[Sequence[str]] = None,
    impact: Optional[List[str]] = None,
    quality_score: Optional[int] = None,
    per_function_limit: int = 5,
    include_base: bool = True,
    min_overlap: int = 0,
    min_code_similarity: float = 0.0,
    require_snippet: bool = False,
    min_core_overlap: int = 0,
) -> Tuple[AuditQuery, List[dict]]:
    query = _extract_keywords(list(files), extra_keywords=extra_keywords)
    index = SoloditFindingsIndex()
    findings_by_function: List[dict] = []
    for file_path in files:
        if not file_path.endswith(".sol"):
            continue
        try:
            text = _read_text(file_path)
        except (OSError, UnicodeDecodeError):
            continue
        for func_name, body in _extract_solidity_functions(text):
            func_keywords = _extract_keywords_from_text(
                body,
                extra_keywords=[func_name],
                include_base=include_base,
            )
            fts_query = _build_fts_query(func_keywords)
            results = index.search(
                fts_query,
                impact=impact,
                min_quality=quality_score,
                limit=per_function_limit,
            )
            if min_overlap > 0:
                results = [r for r in results if _keyword_overlap(r, func_keywords) >= min_overlap]
            if min_code_similarity > 0 or require_snippet:
                filtered = []
                for r in results:
                    snippets = _extract_code_snippets(r)
                    if require_snippet and not snippets:
                        continue
                    best = 0.0
                    for snip in snippets:
                        best = max(best, _code_similarity(body, snip))
                    if best >= min_code_similarity:
                        filtered.append(r)
                results = filtered
            if min_core_overlap > 0:
                results = [r for r in results if _core_overlap(r, body, min_core_overlap)]
            findings_by_function.append(
                {
                    "file": file_path,
                    "function": func_name,
                    "keywords": func_keywords,
                    "findings": results,
                }
            )
    return AuditQuery(keywords=query.keywords, sources=list(files)), findings_by_function


def aggregate_unique_findings(
    per_function_results: List[dict],
    *,
    max_findings: int = 20,
    max_functions_per_finding: int = 3,
) -> List[dict]:
    scores: Dict[str, float] = {}
    store: Dict[str, dict] = {}
    for entry in per_function_results:
        findings = entry.get("findings", []) or []
        for rank, finding in enumerate(findings):
            fid = (
                str(finding.get("id"))
                or str(finding.get("finding_id"))
                or finding.get("source_link")
                or finding.get("title")
                or "unknown"
            )
            weight = max(1, len(findings) - rank)
            scores[fid] = scores.get(fid, 0) + weight
            if fid not in store:
                store[fid] = {
                    "finding": finding,
                    "matches": [],
                }
            if len(store[fid]["matches"]) < max_functions_per_finding:
                store[fid]["matches"].append(
                    {
                        "file": entry.get("file"),
                        "function": entry.get("function"),
                    }
                )

    ordered = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    results: List[dict] = []
    for fid, _score in ordered[:max_findings]:
        results.append(store[fid])
    return results
