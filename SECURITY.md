# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main` branch (latest) | Yes |
| Older commits | No — please update to the latest commit |

## Reporting a Vulnerability

**Please do not disclose security vulnerabilities publicly until they have been coordinated with the maintainers.**

To report a vulnerability, use one of the following channels:

1. **GitHub Security Advisory (preferred):** Open a private security advisory at  
   `https://github.com/jeremylaratro/0xPR0MPT/security/advisories/new`

2. **Email:** If you are unable to use GitHub, contact the maintainers directly through the email address listed on the GitHub profile at `https://github.com/jeremylaratro`.

Please include:
- A clear description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested mitigations

## Scope

0xPR0MPT ships:
- A corpus of live jailbreak payloads (DAN, Developer Mode, Skeleton Key, and related techniques)
- Pickle-file handling code in the supply chain scanner (`scripts/supply_chain/scanner.py`)
- A web dashboard that accepts and renders corpus-derived user data

Vulnerabilities in these components are taken seriously. In particular:

- **Remote code execution** via malicious pickle artifacts or path traversal
- **Stored or reflected XSS** in the dashboard or HTML report output
- **Unauthorized corpus or result access** via unauthenticated dashboard endpoints
- **Payload injection** that causes the tool itself to execute attacker-controlled code during corpus generation or scanning

Out-of-scope items:
- Vulnerabilities in third-party dependencies (report those to the respective upstream projects)
- Findings that require physical access to the machine running the tool

## Response Timeline

| Stage | Target |
|-------|--------|
| Acknowledgement | Within 5 business days |
| Initial assessment | Within 10 business days |
| Fix or mitigation plan | Within 30 business days |
| Coordinated disclosure | Agreed upon with reporter |

## Coordinated Disclosure

We ask that reporters:
- Allow reasonable time for a fix before any public disclosure
- Not exploit the vulnerability beyond what is necessary to demonstrate it
- Not access, modify, or delete data belonging to other users

We commit to:
- Acknowledging reports promptly
- Keeping reporters informed of progress
- Crediting reporters in release notes (unless anonymity is requested)
