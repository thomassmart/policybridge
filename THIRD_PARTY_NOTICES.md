# Third-Party Notices

PolicyBridge includes the following third-party software:

## vmware-analyzer v0.2.1

- Repository: https://github.com/np-guard/vmware-analyzer
- Licence: Apache License 2.0
- Copyright: Copyright 2023- IBM Inc.
- SPDX-License-Identifier: Apache-2.0

Used for NSX DFW connectivity analysis, lint, and Kubernetes policy synthesis.

## netpol-analyzer v1.4.4

- Repository: https://github.com/np-guard/netpol-analyzer
- Licence: Apache License 2.0
- Copyright: Copyright 2023- IBM Inc.
- SPDX-License-Identifier: Apache-2.0

Used for analysing generated Kubernetes network policy connectivity.

## models v0.5.7

- Repository: https://github.com/np-guard/models
- Licence: Apache License 2.0
- SPDX-License-Identifier: Apache-2.0

Transitive dependency providing network transport set types.

## Test fixtures

Sample NSX configuration files in `testdata/nsx/` are derived from
vmware-analyzer's `pkg/data/json/` fixtures under the same Apache 2.0 licence.

## Runtime dependencies

The container image uses:

- `gcr.io/distroless/static-debian12:nonroot` (Google Distroless, licence varies by component)
- `golang:1.24-bookworm` (build stage only, BSD-style licence)
- `node:22-bookworm` (frontend build stage only)

## Independence notice

PolicyBridge is an independent project. Inclusion of NP-Guard software does not
imply endorsement by NP-Guard, VMware, Broadcom, Red Hat, or IBM.
