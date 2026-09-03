# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

If you discover a security vulnerability in PolicyBridge, please report it
responsibly:

1. **Do not** open a public GitHub issue
2. Use GitHub's private vulnerability reporting on this repository
3. Include steps to reproduce and potential impact
4. Allow reasonable time for a fix before public disclosure

## Security model

PolicyBridge is designed as a single-user, local application:

- Binds to localhost by default
- No authentication in the MVP
- Credentials held in memory only
- No persistent storage of sensitive data
- No cluster connectivity

See [docs/security-model.md](docs/security-model.md) for the full security model.

## Scope

The following are **out of scope** for security reports:

- Issues requiring physical access to the machine
- Social engineering attacks
- Denial of service through resource exhaustion (within documented limits)
- Issues in upstream NP-Guard dependencies (report to NP-Guard directly)

## Best practices for users

- Always bind to `127.0.0.1` unless you understand the risks
- Never expose PolicyBridge to untrusted networks without additional protection
- Do not store NSX credentials in configuration files
- Review generated policies before applying to production clusters
