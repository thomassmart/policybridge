# Connectivity Comparison Model

PolicyBridge compares NSX-derived connectivity against generated Kubernetes
policy connectivity. This comparison is **owned by PolicyBridge** — it does not
use `netpol-analyzer diff` (which compares two Kubernetes directories).

## Inputs

### NSX side (from vmware-analyzer)

`connectivity.ConnMap` — a map of permitted connections between NSX endpoints
(VMs, external IPs). Each entry contains:

- Source endpoint (VM name or external IP block)
- Destination endpoint
- `DetailedConnection` with `TransportSet` (protocols/ports) and `Explanation`
  (contributing DFW rule IDs and actions)

Only **permitted** (allowed) connections are in the ConnMap. Denied connectivity
is implicit (absence from the map).

### Kubernetes side (from netpol-analyzer)

`[]Peer2PeerConnection` from `ConnlistAnalyzer.ConnlistFromDirPath` — allowed
connections between Kubernetes workloads (Pods, VMs) and external IP blocks,
derived from generated NetworkPolicy, AdminNetworkPolicy, BaselineAdminNetworkPolicy,
UserDefinedNetwork, Namespace, Pod, and VM manifests.

## Normalised representation

Both sides are normalised into `ConnectivityFact`:

```go
type ConnectivityFact struct {
    SourceIdentity      string            // e.g. "frontend-vm" or "default/my-pod[Pod]"
    DestinationIdentity string
    Direction           string            // "ingress", "egress", or "bidirectional"
    Protocol            string            // "TCP", "UDP", "ICMP"
    PortRange           string            // e.g. "80", "443", "1-65535", "all"
    Allowed             bool
    MappingNotes        []string          // how NSX identity maps to K8s identity
}
```

### Identity mapping

NSX VMs are mapped to generated Kubernetes identities via synthesis labelling:

| NSX identity | Generated K8s label |
|-------------|---------------------|
| Group `backend` | `group__backend: "true"` |
| Tag `DB` | `tag__DB: "true"` |
| VM `frontend-01` | Pod/VM with matching labels in `default` namespace |

Mapping is best-effort. When a mapping cannot be established, the fact is
categorised as **uncomparable**.

## Comparison categories

| Category | Definition |
|----------|------------|
| **exact** | Same mapped source/destination, same protocol/port allow set |
| **missing** | Present in NSX ConnMap but absent or narrower in K8s connlist |
| **additional** | Present in K8s connlist but absent or narrower in NSX ConnMap |
| **uncomparable** | Cannot be compared due to unsupported or ambiguous mapping |

### Uncomparable reasons

- ICMP connectivity (cannot be expressed in NetworkPolicy)
- IPv6 addresses (not supported by upstream analysis)
- Unmatched VM-to-Pod/VM name mapping
- External IP block representation differences between models
- `{ingress-controller}` peers from Ingress/Route analysis
- `entire-cluster` exposure peers from exposure analysis
- Empty or ambiguous endpoint group mappings
- Nested group expressions that fell back to group labels

## Severity indicators

| Severity | Applied when |
|----------|-------------|
| **critical** | Broad/unrestricted connectivity missing from generated policies |
| **high** | Specific allowed connection missing from generated policies |
| **medium** | Additional connectivity introduced by generated policies |
| **low** | Minor port/protocol differences |
| **info** | Uncomparable items with known limitations |

## Output

The comparison produces:

1. **Summary counts** per category
2. **Filterable table** of individual facts with category, severity, and mapping notes
3. **Connectivity difference visualisation** (topology overlay)
4. **Explanations** tied back to NSX rule IDs and generated policy resource names
5. **Limitations section** listing what could not be compared and why

Results are exported as `connectivity-comparison.json` in Kustomize ZIP exports
and included in the validation API response.

## What PolicyBridge does not claim

- **Never claim full equivalence** between NSX and generated policies.
- Incomplete analysis is a first-class result, not hidden behind a pass/fail.
- The comparison validates connectivity overlap, not semantic policy equivalence.
- Exposure analysis findings are reported separately and do not affect the
  connectivity comparison categories.
