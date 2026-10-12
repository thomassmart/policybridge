# PolicyBridge Architecture

PolicyBridge is an independent, containerised web application that wraps NP-Guard's
`vmware-analyzer` and `netpol-analyzer` utilities. It provides a guided workflow
for analysing VMware NSX Distributed Firewall configuration and converting
microsegmentation intent into Kubernetes/OpenShift Virtualization network policies.

**PolicyBridge is not endorsed by NP-Guard, VMware, Broadcom, Red Hat, or IBM.**

## Pinned upstream versions

| Component | Version | Licence |
|-----------|---------|---------|
| `github.com/np-guard/vmware-analyzer` | v0.2.1 | Apache-2.0 |
| `github.com/np-guard/netpol-analyzer` | v1.4.4 | Apache-2.0 |
| `github.com/np-guard/models` (transitive) | v0.5.7 | Apache-2.0 |
| Go toolchain | 1.24+ | — |

## System overview

```text
┌─────────────────────────────────────────────────────────────┐
│  Browser (PatternFly React wizard)                          │
│  - Never constructs CLI arguments                           │
│  - No localStorage for dumps or credentials                 │
└──────────────────────────┬──────────────────────────────────┘
                           │ JSON REST API (OpenAPI)
┌──────────────────────────▼──────────────────────────────────┐
│  Go HTTP server (cmd/policybridge)                          │
│  ├── internal/api        HTTP handlers, job orchestration   │
│  ├── internal/session    In-memory sessions, temp dirs      │
│  ├── internal/adapters/nsx      vmware-analyzer wrapper     │
│  ├── internal/adapters/netpol   netpol-analyzer wrapper     │
│  ├── internal/compare    NSX ↔ K8s connectivity comparison    │
│  ├── internal/export     YAML + Kustomize ZIP generation    │
│  └── internal/redact     Credential/secret sanitisation     │
└──────────────────────────┬──────────────────────────────────┘
                           │ Go library imports (not CLI)
┌──────────────────────────▼──────────────────────────────────┐
│  NP-Guard libraries (pinned versions)                       │
│  ├── vmware-analyzer/pkg/runner   collect/analyze/lint/gen  │
│  └── netpol-analyzer/pkg/netpol/connlist  dir-based analysis│
└─────────────────────────────────────────────────────────────┘
```

## Integration boundaries

### vmware-analyzer adapter (`internal/adapters/nsx`)

The adapter imports only public packages from `vmware-analyzer`:

- **`pkg/runner`** — primary entry point via functional options (`WithCmd`,
  `WithNSXURL`, `WithResourcesInputFile`, `WithSynthesisDir`, etc.). The Runner
  orchestrates collect, analyze, lint, and generate operations.
- **`pkg/collector`** — `FromJSONString` for dump validation, `CollectResources`
  for live collection, `ValidateNSXConnection` for connection testing.
- **`pkg/collector/anonymizer`** — `AnonymizeNsx` for dump anonymisation.
- **`pkg/analyzer/connectivity`** — `ConnMap` for structured connectivity data.

The adapter does **not** import `internal/` packages from vmware-analyzer (they
are not accessible from external modules).

All adapter calls are serialised with a process-wide mutex because
`logging.Init` is global and Runner prints to stdout.

### netpol-analyzer adapter (`internal/adapters/netpol`)

The adapter imports `pkg/netpol/connlist`:

- `NewConnlistAnalyzer` with `WithExplanation()`, `WithExposureAnalysis()`,
  `WithOutputFormat("json")`.
- `ConnlistFromDirPath` — analyses generated YAML manifests from a directory.
- **Never** uses kubeconfig or live-cluster APIs.

The `diff` command compares two Kubernetes directories. PolicyBridge does **not**
use it for NSX-vs-K8s comparison; that is handled by the comparison normaliser.

## Session and job model

Each user session is identified by an HTTP-only, SameSite=strict cookie. Sessions
hold:

- NSX credentials (in memory only, wiped on expiry/shutdown)
- Path to an isolated temporary directory for dumps, generated YAML, and exports
- Job state (idle, running, completed, failed) with cancellable context
- Cached analysis, generation, and comparison results

Only one conflicting operation runs per session at a time.

## API design

The REST API is defined in `api/openapi.yaml`. TypeScript types are generated
from the OpenAPI spec for the frontend. Key endpoint groups:

| Group | Endpoints |
|-------|-----------|
| Session | `POST /api/v1/sessions`, `GET /api/v1/sessions/current` |
| Source | `POST /api/v1/sessions/{id}/source/upload`, `POST .../source/connect`, `POST .../source/test` |
| Summary | `GET /api/v1/sessions/{id}/summary` |
| Analysis | `POST .../analyze`, `GET .../analysis`, `GET .../analysis/connectivity` |
| Generation | `POST .../generate`, `GET .../policies` |
| Validation | `POST .../validate`, `GET .../validation` |
| Export | `POST .../export/yaml`, `POST .../export/kustomize` |
| About | `GET /api/v1/about` |
| Health | `GET /healthz` |

Long-running operations return a job ID; clients poll `GET .../jobs/{jobId}`.

## Frontend architecture

React 19 + TypeScript + PatternFly 6. A six-step PatternFly Wizard drives the workflow:

1. **Source** — connect to NSX Manager or upload a dump (single Continue action)
2. **NSX intent** — review collected stats, connectivity map, and DFW lint (analysis auto-runs)
3. **Rule selection** — choose which DFW rules to include in synthesis (all selected by default)
4. **Generate** — OpenShift project / networking target, synthesis options, then generate + validate
5. **Results** — generated policies and NSX validation comparison (generate + validate auto-run)
6. **Export** — download YAML or Kustomize ZIP

The UI uses PatternFly Page + Masthead (About, New analysis) with wizard navigation as the only process map. Long-running jobs show in-step progress and an expandable activity log.

Key libraries:
- `@patternfly/react-core` — layout, forms, wizard, alerts
- `@patternfly/react-topology` — interactive connectivity graph
- `@patternfly/react-table` — mapping and lint tables

## Container image

Multi-stage build:
1. **frontend** — Node.js builds React app to `web/dist`
2. **backend** — Go compiles with embedded frontend assets
3. **runtime** — minimal image, non-root user, health check on `/healthz`

```bash
podman run --rm -p 127.0.0.1:8080:8080 policybridge:latest
```

## Repository layout

```text
cmd/policybridge/           Main entry point
internal/
  api/                      HTTP handlers, middleware, job runner
  session/                  Session store, temp dirs, credentials
  adapters/nsx/             vmware-analyzer integration
  adapters/netpol/          netpol-analyzer integration
  compare/                  Connectivity comparison normaliser
  export/                   YAML and Kustomize ZIP builders
  redact/                   Secret redaction utilities
  version/                  Build-time version info
web/                        React + PatternFly frontend
api/openapi.yaml            API specification
docs/                       Architecture and support documentation
testdata/nsx/               Attributed upstream fixtures
Containerfile               Multi-stage OCI image
Makefile                    Build, test, lint tasks
```

## Design decisions

1. **Library over CLI** — Direct Go imports avoid subprocess overhead, credential
   exposure in argv, and shell injection risks.
2. **No database** — Single-user, ephemeral sessions suit in-memory storage.
3. **Localhost default** — Bind to `127.0.0.1`; warn if exposed beyond loopback.
4. **No cluster connectivity** — All Kubernetes analysis is from generated YAML
   on disk, never from a live cluster.
5. **Comparison is PolicyBridge-owned** — NP-Guard provides connectivity models
   for each side; PolicyBridge normalises and compares them without reimplementing
   analysis algorithms.
