# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.x (main) | Yes |

## Reporting a Vulnerability

**Please do not open public GitHub issues for security vulnerabilities.**

Email security reports to: **security@sentinelwall.dev**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgement within 48 hours. We aim to release a patch within 14 days for critical issues.

We follow coordinated disclosure and will credit reporters in release notes (unless you prefer to remain anonymous).

## Threat Model

SentinelWall is designed to protect Linux hosts from network-based attacks. It is **not** designed to:

- Protect against physical access
- Protect against compromised root users
- Prevent kernel exploits or privilege escalation from compromised processes

## Security Hardening Checklist

When deploying SentinelWall in production:

- [ ] Change the default admin password (`SENTINEL_ADMIN_PASSWORD`)
- [ ] Set a strong `jwt_secret` in config (at least 32 random bytes)
- [ ] Bind the API to `127.0.0.1` unless remote access is needed
- [ ] Enable TLS if exposing the API on a network
- [ ] Restrict `cors_origins` to your actual frontend domain
- [ ] Set `trusted_networks` to only your management IPs
- [ ] Review the active firewall profile for your use case
- [ ] Enable geo-IP blocking if you have no legitimate users in high-risk countries
- [ ] Configure threat intel feeds (AbuseIPDB, CrowdSec) for enriched detection
- [ ] Monitor `/var/log/sentinelwall/audit.log` for admin actions
- [ ] Rotate API tokens regularly

## CVE Disclosure History

No CVEs have been issued at this time.
