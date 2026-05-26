# Security Policy

## Supported Versions

Only the latest released minor version receives security updates.

## Reporting a Vulnerability

Please **do not** open a public issue for security vulnerabilities.

Use GitHub's private vulnerability reporting:
[Report a vulnerability](https://github.com/classicPintus/web-push-spring-boot-starter/security/advisories/new)

You will receive an acknowledgement within 7 days. After triage, expect a fix
or mitigation timeline within 30 days for confirmed issues.

Please include:

- a clear description of the issue and its impact;
- steps to reproduce (PoC if possible);
- affected version(s);
- any suggested mitigation.

## Scope

This project performs ECDH P-256 key agreement, HKDF SHA-256 key derivation,
AES-128-GCM content encryption and ES256 JWT signing using only the JDK's JCA
providers. Cryptographic findings, signature verification issues and key
handling problems are in scope.
