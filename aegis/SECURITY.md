# Security policy

## Reporting
Email the security owner listed in CODEOWNERS with a description, reproduction steps, and impact. Do not open a public issue. Acknowledgement within 2 business days; resolution plan within 10.

## Baseline
- API surface: OWASP ASVS 4.0 Level 2. Authentication and `governance/`: Level 3.
- Delivery pipeline: NIST SP 800-218 (SSDF). Release artefacts are Sigstore-signed with a CycloneDX SBOM.

## Controls in this codebase
| Threat (STRIDE) | Control | Where |
|---|---|---|
| Spoofing | Bearer token, constant-time comparison | `api/v1/security.py` |
| Tampering | Hash-chained audit log, verified on every read | `governance/audit.py` |
| Repudiation | Every evaluation and API mutation is audited with actor | `governance/engine.py`, `api/v1/app.py` |
| Information disclosure | Log redaction processor; CSP `default-src 'self'`; no secrets in URLs | `adapters/logging.py`, middleware |
| Denial of service | 256 KiB body limit, per-client rate limit, step ceiling | middleware, `RunSpec` |
| Elevation of privilege | Boundaries read-only after load; engine has no mutation API; non-root container | `governance/engine.py`, `Dockerfile` |

## Supply chain
Dependencies pinned via lockfile; `pip-audit` and `gitleaks` in CI; base images pinned by digest in production.
