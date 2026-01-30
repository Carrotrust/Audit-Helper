# Audit Helper

Audit Helper lets auditors and developers scan a codebase for patterns that resemble known bugs reported in Solodit, using the Solodit API plus a local cache/index. It helps surface similar historical findings while reviewing new contracts.

## Setup

Create a virtual environment and install in editable mode:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

Set the API key as an environment variable:

```bash
export SOLODIT_API_KEY="your_key_here"
```

Optional environment variables:
- `SOLODIT_BASE_URL` (default: `https://solodit.cyfrin.io/api/v1/solodit`)
- `SOLODIT_CACHE_PATH` (default: `~/.cache/solodit_cache.sqlite`)
- `SOLODIT_CACHE_TTL_DAYS` (default: `30`)

## CLI Usage

Basic commands:

```bash
audit-helper search "reentrancy"
audit-helper request --path "/search" --params "q=reentrancy"
audit-helper findings --filters-json '{"impact":["HIGH"],"keywords":"oracle"}' --page 1 --page-size 20
```

Scan a codebase (write a report):

```bash
audit-helper sync --page-size 100

audit-helper scan /path/to/contracts \
  --impact HIGH --impact MEDIUM --impact LOW \
  --unique-findings 20 \
  --min-core-overlap 1 --min-overlap 2 \
  --out scan.md
```

If you prefer module execution:

```bash
python -m cli scan /path/to/contracts --unique-findings 20 --out scan.md
```

### How to use it

Audit Helper can scan an entire folder or a specific list of files:

- **Scan a whole folder:** point the tool at the root of the codebase you want to review.
- **Scan specific files:** create a newline-delimited file list and pass it with `--file-list`.

Example (scan a folder):

```bash
audit-helper scan /path/to/project --unique-findings 20 --out scan.md
```

Example (scan specific files):

```bash
cat > /tmp/scope.txt <<'EOF'
contracts/Foo.sol
contracts/Bar.sol
EOF

audit-helper scan /path/to/project \
  --file-list /tmp/scope.txt \
  --unique-findings 20 \
  --out scan.md
```

### Important flags

- `--impact` accepts one or more severities (HIGH, MEDIUM, LOW, INFO). If omitted, all severities are included.
- `--quality-score` filters findings by minimum Solodit quality score (1–5). Omit it to allow all.
- `--keyword` adds a core term (e.g., "reentrancy", "oracle") to bias matching.
- `--top N` limits the number of matches returned per scan (default: 20).
- `--per-function` groups matches by each function in the codebase.
- `--unique-findings N` returns distinct findings across the whole scan (deduped).
- `--strict` raises the matching bar (useful to reduce false positives).
- `--min-overlap` controls the minimum keyword overlap between code and finding text.
- `--min-core-overlap` sets the minimum overlap on core security terms.
- `--require-snippet` only matches findings that include code snippets.
- `--min-code-similarity` sets how similar code snippets must be to match (0.00–1.00).
- `--out` writes a markdown report (e.g., `scan.md`) instead of printing to stdout.
- `sync --resume` continues from the last saved page to avoid re-downloading.

### Match locations

Use `--per-function` or `--unique-findings` to include **file + function** match locations in the report. This is the mode that tells you which exact function in your codebase resembles a known buggy pattern.

## Python Usage

```python
from client import SoloditClient

client = SoloditClient()
findings = client.findings(
    filters={
        "impact": ["HIGH"],
        "keywords": "oracle",
        "qualityScore": 3,
        "sortField": "Quality",
        "sortDirection": "Desc",
    },
    page=1,
    page_size=20,
)
print(findings)
```

## Notes

- Results are cached by request signature to speed up repeat queries.
- Matches are **not** guaranteed to be confirmed bugs. Always review and validate results to rule out false positives.

## Contributing

Contributions are welcome. Feel free to open issues or submit pull requests with improvements, new features, or bug fixes.
