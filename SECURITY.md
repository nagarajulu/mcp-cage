# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `0.4.x` | :white_check_mark: Active |
| `< 0.4.0` | :x: Upgrade to `>= 0.4.0` |

## Reporting a Vulnerability

We take the security of `mcp-cage` seriously. If you discover a security vulnerability, bypass, or false-negative in `mcp-cage` (across Plane A JSON-RPC wire filtering, Plane B lifecycle hooks, SQLite WAL state management, or `compile-sandbox` kernel profile generation), please report it privately:

1. **GitHub Private Vulnerability Reporting (Preferred):**  
   Submit a confidential report directly via [**GitHub Security Advisories (`Report a vulnerability`)**](https://github.com/nagarajulu/mcp-cage/security/advisories/new).
2. **Direct Email:**  
   You may also email [**nagarajulu.a@gmail.com**](mailto:nagarajulu.a@gmail.com) with `[SECURITY] mcp-cage` in the subject line.

### Response Timeline & Coordinated Disclosure
- **Acknowledgment:** Within 48 hours of receipt.
- **Triage & Fix:** Within 7–14 days for confirmed vulnerabilities.
- **Credit:** We gladly issue official GitHub Security Advisories (GHSAs) and credit reporters in release notes upon patch publication.
