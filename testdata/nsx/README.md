# NSX test fixtures

Attributed samples from [vmware-analyzer v0.2.1](https://github.com/np-guard/vmware-analyzer/tree/v0.2.1/pkg/data/json) (Apache-2.0, Copyright 2023- IBM Inc.):

| File | Purpose |
|------|---------|
| `Example1.json` | Connectivity analysis and synthesis demos |
| `Example2.json` | Additional connectivity scenarios |
| `one_redundant_covered_by_2_rules.json` | DFW lint / shadowed rule testing |

These three attributed samples are committed. Additional dumps in this directory stay gitignored so customer NSX configs cannot be added by accident.

Re-download with `make download-fixtures` if they are missing locally.
