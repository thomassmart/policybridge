# PolicyBridge

A containerised web GUI for analysing VMware NSX Distributed Firewall configuration
and converting microsegmentation intent into Kubernetes/OpenShift Virtualization
network policies.

**PolicyBridge is an independent project and is not endorsed by NP-Guard, VMware,
Broadcom, Red Hat, or IBM.**

## Features

- Collect NSX configuration from NSX Manager or upload a resource dump
- Visualise permitted NSX connectivity
- Identify shadowed, ineffective, and broad DFW rules
- Generate Kubernetes and OpenShift Virtualization microsegmentation resources
- Validate generated policies with netpol-analyzer
- Compare connectivity against original NSX intent
- Export apply-ready YAML or GitOps Kustomize ZIP

## Quick start

```bash
# Build and run with Podman
make container
podman run --rm -p 127.0.0.1:8080:8080 policybridge:latest
```

The container image listens on `0.0.0.0:8080` internally so port publishing works; bind the host port to loopback as shown above.

```bash
# Or run locally for development
make dev
```

Open http://127.0.0.1:8080 in your browser.

## Container image (GHCR)

Images are published to GitHub Container Registry from `main` and version tags.

```bash
# Authenticate (required for a private package)
echo "$GITHUB_TOKEN" | podman login ghcr.io -u USERNAME --password-stdin

podman pull ghcr.io/thomassmart/policybridge:latest
podman run --rm -p 127.0.0.1:8080:8080 ghcr.io/thomassmart/policybridge:latest
```

## Pinned dependencies

| Component | Version |
|-----------|---------|
| vmware-analyzer | v0.2.1 |
| netpol-analyzer | v1.4.4 |
| Go | 1.24+ |

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `POLICYBRIDGE_LISTEN_ADDR` | `127.0.0.1` | Bind address |
| `POLICYBRIDGE_LISTEN_PORT` | `8080` | Listen port |
| `POLICYBRIDGE_LOG_LEVEL` | `info` | Log level |

## Development

```bash
# Install Go dependencies
make mod

# Run tests
make test

# Format code
make fmt

# Lint
make lint
```

See [docs/architecture.md](docs/architecture.md) for architecture details.

## Licence

Apache License 2.0. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
