# NSX Support

This document records what `vmware-analyzer v0.2.1` actually supports, based on
upstream documentation and source code. PolicyBridge does not extend this support.

## API reference

vmware-analyzer references the [NSX-T Data Center REST API](https://developer.broadcom.com/xapis/nsx-t-data-center-rest-api/latest/).
No specific NSX product version is pinned by the upstream project.

PolicyBridge displays **"NSX version: not reported by the collector"** unless a
version string is present in the collected data.

## Collected resources

The collector gathers these NSX resources via REST API:

| Resource | API path |
|----------|----------|
| Virtual machines | `api/v1/fabric/virtual-machines` |
| Virtual network interfaces | `api/v1/fabric/vifs` |
| Services | `policy/api/v1/infra/services` |
| Segments (+ ports) | `policy/api/v1/infra/segments` |
| Tier-0 gateways (+ NAT) | `policy/api/v1/infra/tier-0s` |
| Tier-1 gateways (+ NAT) | `policy/api/v1/infra/tier-1s` |
| Domains | `policy/api/v1/infra/domains` |
| Groups (+ members) | `policy/api/v1/infra/domains/{id}/groups` |
| Security policies (+ rules) | `policy/api/v1/infra/domains/{id}/security-policies` |
| Gateway policies | `policy/api/v1/infra/domains/{id}/gateway-policies` |
| Redirection policies | `policy/api/v1/infra/domains/{id}/redirection-policies` |
| Firewall rules (by ID) | `api/v1/firewall/rules/{id}` |

## Topology resources considered for analysis

- VMs
- Segments
- T1 Gateway
- T0 Gateway

Analysis endpoints are VMs from `GET api/v1/fabric/virtual-machines`.

## Supported DFW features

- Protocols: **TCP, UDP, ICMP**
- Group expressions over tags (non-nested)
- Security policy rules with allow/deny/jump-to-app actions
- Service groups and individual services

## Unsupported or limited features

| Feature | Status |
|---------|--------|
| Ethernet category rules | Not supported |
| Source/destination groups with IP addresses | Not supported |
| IPv6 protocols and addresses | Not supported |
| Nested NSX group expressions | Not fully supported (synthesis falls back to group labels) |
| Multiple NSX domains | Single domain assumed |
| ICMP in Kubernetes NetworkPolicy | Cannot be expressed in target policies |
| Custom CA for NSX TLS | Not supported (system trust store only) |

## Resource dump format

Uploads must be JSON matching `collector.ResourcesContainerModel`:

```json
{
  "services": [],
  "virtual_machines": [],
  "virtual_network_interface": [],
  "segments": [],
  "tier0": [],
  "tier1": [],
  "domains": [
    {
      "id": "...",
      "resources": {
        "security_policies": [],
        "gateway_policies": [],
        "redirection_policies": [],
        "groups": []
      }
    }
  ]
}
```

Create a compatible dump with:

```bash
nsxanalyzer collect -f config.json --host https://nsx-manager.example.com
```

## TLS behaviour

**Important:** The upstream `nsxanalyzer` CLI defaults to retrying NSX connections
with `InsecureSkipVerify` when certificate verification fails. PolicyBridge
**inverts this default**:

- TLS verification is **enabled by default** (`WithDisableInsecureSkipVerify(true)`).
- Users may opt into an insecure exception via an Advanced setting, clearly
  labelled as temporary and insecure.
- PolicyBridge never silently retries with verification disabled.
- Custom CA certificates are **not supported** by the upstream collector. Only
  the system trust store is used. No CA upload field is provided.

## Synthesis limitations

- Flattening prioritized allow/deny/jump-to-app rules into flat allow rules is
  exponential in rule count. Provide disjoint group/tag hints for effective synthesis.
- `--hints-inference` infers disjoint groups from the current NSX snapshot; review
  inferred hints before relying on them.
- `--policy-optimization-level max` may omit policies not evidenced by current
  VM-to-namespace mappings.
- Synthesized equivalence to NSX intent is not guaranteed due to expression power
  differences between NSX DFW and Kubernetes NetworkPolicy.

## Group member types collected

Supported: Segment, SegmentPort, VirtualMachine, VirtualNetworkInterface,
IPAddress, TransportNode, Group.

Unsupported member types are logged as warnings during collection.

## Collection duration

Live collection uses the vmware-analyzer collector, which pauses **200 ms between
every NSX REST API call**. It walks VMs, segments, groups (with multiple member
queries per group), security policies, DFW rules, services, and related objects.

Rough expectations:

| Environment | Typical duration |
|-------------|------------------|
| Small lab (few VMs, handful of DFW rules) | 1–5 minutes |
| Medium (many groups or rules) | 5–15 minutes |
| Large | 30+ minutes |

VM count alone does not determine duration — **groups and DFW rules** drive most
API calls. Test connection only lists VMs (one quick call); full collection is
much slower. Use the Activity console for elapsed-time updates during collection.

## Test fixtures

Sample dumps for development are in `testdata/nsx/`. See `testdata/nsx/README.md`
for download instructions from vmware-analyzer fixtures.
