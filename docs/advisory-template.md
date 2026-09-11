# Advisory template

Copy this file to `vulns/NN-<slug>/README.md` and fill every section with real
data. Never leave an illustrative HTTP response in `Evidence`; paste the raw
output of an actual run captured under `evidence/`.

```markdown
# <short title>

- **Product:** i-Educar <affected flow/version> (portabilis/i-educar)
- **Type / CWE:** <e.g. CWE-89 SQL Injection> — <cwe source URL>
- **Severity:** <CVSS 3.1 or 4.0 vector + score> (label as estimate if you scored it)
- **Affected version:** <range/commit>
- **Endpoint(s):** `<METHOD /path>` — parameter(s): `<param>`
- **Authentication:** <none | login required | profile X required>
- **Status:** VERIFIED against local lab (<date>) | UNVERIFIED — <reason>

## Summary
One paragraph: what is broken, where, and the impact.

## Root cause
`<file>:<line>` + short snippet + explanation (string concatenation, missing
output encoding, missing authorization check, etc.).

## Proof of concept
Numbered steps (setup, exact request, expected result). Reference `poc.py` and
the exact orchestrator command.

## Evidence
Raw `poc.py` output (paste verbatim in a code block) + paths under `evidence/`.

## Screenshots
![caption](evidence/screenshots/NN-slug-NN-what.png)

## Impact
What an attacker gains or changes. No hyperbole.

## Timeline
- <date>: reported to maintainer (<channel/link>)
- <date>: follow-up
- <date>: 90 days of silence
- <date>: final public-disclosure notice
- <date>: public disclosure

## Mitigation
What to apply in code/config until a patch exists.

## References
- <link to the GitHub report/issue>
- <canonical URL of this advisory>
```
