# Security Policy

## Supported Versions

NetWatch AI is currently in active prototype development. Security fixes are applied to the **`main` branch** only.

| Version | Supported |
|---------|-----------|
| `main` (latest) | ✅ Yes |
| Older releases | ❌ No |

## Reporting a Vulnerability

**Please do not report security vulnerabilities via public GitHub Issues.**

If you discover a security vulnerability, please report it responsibly through one of the following channels:

1. **GitHub Private Vulnerability Reporting** (preferred):
   Use [GitHub's private reporting feature](https://github.com/growlf/netyeti-netwatcher/security/advisories/new) to submit a confidential report.

2. **Email**: Contact the maintainer directly at the email address listed on their [GitHub profile](https://github.com/growlf).

### What to Include

Please provide as much of the following information as possible:

- **Description**: A clear description of the vulnerability.
- **Impact**: What an attacker could achieve by exploiting it.
- **Steps to reproduce**: A minimal reproduction scenario.
- **Affected component**: Which file(s) or function(s) are affected.
- **Suggested fix** (optional): If you have a proposed fix, please include it.

### Response Timeline

- **Acknowledgement**: Within 48 hours of receipt.
- **Status update**: Within 7 days.
- **Fix + disclosure**: We aim to resolve critical issues within 30 days.

## Security Considerations for Self-Hosted Deployments

NetWatch AI is designed to run entirely on your local network. Keep the following in mind:

- The agent dashboard (port 8085) has **no authentication by default**. Do not expose it to the internet. Use a reverse proxy with authentication if remote access is required.
- SSH credentials and Proxmox tokens are stored in plaintext YAML files in `config/host_vars/`. Ensure this directory is not world-readable (`chmod 700 config/host_vars`).
- The nmap scan uses polite timing but may still trigger IDS/IPS alerts on some networks.
- `verify_ssl=False` is used for Proxmox connections by default (self-signed certs are common in homelabs). A warning is logged when this is active.
