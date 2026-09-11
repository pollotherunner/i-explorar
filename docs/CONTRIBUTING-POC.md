# PoC contract

Every `vulns/NN-<slug>/poc.py` follows this contract. There is no metadata
sidecar: the `VULN` dict below is the only place vulnerability data lives.

```python
VULN = {
    "id": "01",
    "slug": "<slug>",
    "title": "<title>",
    "product": "i-Educar",
    "affected_version": "<version>",
    "cwe_id": "CWE-89",
    "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
    "cwe_source_url": "https://cwe.mitre.org/data/definitions/89.html",
    "cwe_confidence": "high",          # high | medium | low
    "cwe_justification": "why this CWE and not the neighbouring one",
    "cvss_vector": "CVSS:3.1/...",
    "cvss_score": 0.0,
    "endpoint": "POST /path",
    "params": ["x"],
    "precondition": "none",            # none | login | profile:<name>
    "reported_at": "YYYY-MM-DD",
    "followups": ["YYYY-MM-DD"],
    "silence_days": 0,
    "status": "verified",              # verified | unverified | blocked
    "blocked_reason": "",              # required when status != verified
    "screenshots": ["evidence/screenshots/NN-slug-01-what.png"],
    "advisory_url": "https://github.com/<user>/i-explorar/blob/main/vulns/NN-<slug>/README.md",
}

def run(target: str, *, verbose: bool = False) -> dict:
    """Returns {'vulnerable': bool, 'evidence': [str, ...], 'notes': str}."""

def main(argv: list[str]) -> int:
    """argparse CLI: --target, --json, --verbose, --print-evidence, --no-color."""
```

## Rules

- **Python 3 standard library only.** `urllib`, not `requests`.
- **Fail closed on the target.** Call `lib.lab_guard.check_target(target)` before
  anything else; the only accepted hosts are `127.0.0.1`, `localhost`, `::1`.
- **Never hardcode credentials.** Use `lib.credentials.credentials("admin")`,
  which reads the gitignored `lab/CREDENTIALS.md` (or the
  `IEXPLORAR_<ROLE>_PASSWORD` environment variables).
- **Select the lab checkout with `lib.lab.lab_dir()`.** It defaults to
  `lab/i-educar` (the 2.11.0 release lab) and honours the `IEXPLORAR_LAB`
  environment variable for another checkout.
- **Import-safe.** Importing the module must not perform network or shell
  activity; everything happens inside `run()` / `main()`.
- **Writes raw evidence.** Use `lib.evidence.EvidenceLog` so each run appends
  `evidence/run-<timestamp>.log` with the real output and timestamps.
- **Minimal default output:** the ASCII banner, the ordered exploit sequence
  (`[+]` per step, condensed from the raw log) and one final
  `[+] VULNERABLE — ...` line. `--verbose` adds the endpoint, evidence path and
  exact command; `--print-evidence` dumps the whole raw log.
- **Minimal and non-destructive.** Read-only SQL payloads, one or two rows of
  proof, no `DROP`/`DELETE` of real data, no DoS, no persistence.
- **Standalone and importable.** `python3 vulns/NN-<slug>/poc.py --target
  http://127.0.0.1:8080` exits non-zero when the target is not vulnerable.
