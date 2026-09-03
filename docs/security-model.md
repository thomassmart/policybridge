# Security Model

PolicyBridge is a single-user, local application designed for analysing NSX
configuration and generating Kubernetes network policies without persisting
sensitive data.

## Threat model

| Threat | Mitigation |
|--------|------------|
| Credential exposure | In-memory only; never written to disk, logs, URLs, or browser storage |
| Network exposure | Binds to 127.0.0.1 by default; warns if bound beyond loopback |
| Command injection | No shell invocation; NP-Guard libraries called via Go imports |
| Path traversal | Validated file paths within session temp directories |
| Zip Slip | ZIP entry paths validated before extraction/writing |
| Malicious uploads | Size limits, JSON structure validation, content-type checks |
| Information leakage | Credential redaction in all error messages and logs |
| Session hijacking | HTTP-only, SameSite=strict cookies; no persistent sessions |

## Credential handling

NSX credentials (URL, username, password) are:

1. Received via HTTPS POST body (never query parameters)
2. Stored in the session struct in process memory
3. Passed to vmware-analyzer Runner options (not environment variables)
4. **Never** written to:
   - Disk (including temp directories)
   - Application logs
   - Error reports returned to the frontend
   - Browser localStorage or sessionStorage
   - URLs or redirect parameters
5. Wiped when the session expires or the application exits

The redaction layer (`internal/redact`) sanitises all error messages and log
output, replacing credential values with `[REDACTED]`.

## Session lifecycle

```text
Created → Active → Expired/Closed
              ↓
         Temp dir deleted
         Credentials wiped
         Analysis results discarded
```

- Sessions expire after configurable idle timeout (default: 2 hours)
- A background goroutine cleans expired sessions
- Application shutdown triggers cleanup of all sessions
- Session cookies: `HttpOnly`, `Secure` (when TLS), `SameSite=Strict`

## Temporary file handling

Each session gets an isolated directory under the system temp root:

```text
/tmp/policybridge-{session-id}/
  dump.json              NSX resource dump (if uploaded/collected)
  k8s_resources/         Generated YAML manifests
  analysis/              Analysis output files
  export/                Export artefacts
```

- Directories are created with `0700` permissions
- All files deleted on session expiry or application exit
- Upload size limit: 100 MB (configurable via `POLICYBRIDGE_MAX_UPLOAD_BYTES`)
- Only `.json` uploads accepted for NSX dumps

## TLS for NSX connections

PolicyBridge inverts the upstream default:

| Setting | Upstream default | PolicyBridge default |
|---------|-----------------|---------------------|
| TLS verification | Off (retries with InsecureSkipVerify) | **On** |
| Custom CA | Not supported | Not offered |
| Insecure exception | Implicit retry | Explicit opt-in with warning label |

When the user enables the insecure TLS exception:
- A prominent warning is displayed in the UI
- The setting is labelled "Temporary insecure TLS exception"
- The choice is not persisted across sessions

## Network binding

| Variable | Default | Description |
|----------|---------|-------------|
| `POLICYBRIDGE_LISTEN_ADDR` | `127.0.0.1` | Bind address |
| `POLICYBRIDGE_LISTEN_PORT` | `8080` | Listen port |

If the bind address is not a loopback address, the application logs a warning
and the UI displays a security notice. No authentication is provided in the MVP.

## Input validation

### File uploads
- Maximum size enforced before reading body
- Content-Type must be `application/json` or `application/octet-stream`
- JSON must unmarshal to `ResourcesContainerModel` structure
- Top-level keys validated against expected schema

### API parameters
- Session IDs validated as UUIDs
- File paths resolved within session temp directory (no `..` traversal)
- Enum values validated against allowed sets
- No user input passed to shell commands

### ZIP generation
- Entry paths checked for `..` prefix (Zip Slip prevention)
- Absolute paths rejected
- Symlink entries rejected

## Logging

- No NSX credentials in logs
- No raw NSX dump content in logs
- No generated YAML content in logs at INFO level
- Structured logging with session ID (not credentials)
- Log level configurable via `POLICYBRIDGE_LOG_LEVEL` (default: `info`)

## Container security

- Multi-stage build; runtime image contains only the binary and CA certificates
- Non-root user (`policybridge`, UID 65532)
- Read-only root filesystem (writable temp only)
- No shell in runtime image
- Health check on `/healthz` (no sensitive data)
- No external telemetry or analytics
- No CDN-hosted runtime assets
- No dependency on internet connection at runtime (except user-initiated NSX collection)

## What PolicyBridge does not do

- Store credentials between sessions
- Connect to Kubernetes or OpenShift clusters
- Accept kubeconfig files
- Apply resources to any cluster
- Integrate with Git providers
- Send data to external services
- Provide multi-user authentication
