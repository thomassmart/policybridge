# Mapping rewrite fixtures

Golden YAML for post-synthesis namespace and peer rewrite.

| File | Role |
|------|------|
| `peers_before.yaml` | Broken vmware-analyzer-style peers (`Seg-*` namespaceSelectors for ANY and tag peers) |
| `peers_after.yaml` | Expected shape after Target namespace remap to `tom-testing` plus peer normalisation |

Used by `internal/mapping` tests (`TestRewriteNetworkPolicyPeers_FleetGolden`).

## Before → after (Fleet-style)

**ANY egress (DNS):** `to.namespaceSelector In [Seg-…, default]` (+ optional `0.0.0.0/0`) → ports only, no `to`.

**Tag → tag:** `to.namespaceSelector` + `podSelector` Exists → `to.podSelector` Exists only.

**ANY ingress:** `from.namespaceSelector In [Seg-…]` → `ingress: [{}]`.
