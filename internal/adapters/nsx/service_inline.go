package nsx

import (
	"strings"

	"github.com/np-guard/vmware-analyzer/pkg/collector"
	nsxgen "github.com/np-guard/vmware-analyzer/pkg/configuration/generated"
)

// wellKnownL4 is used when a named NSX service is referenced but not present in the dump.
// vmware-analyzer drops rules whose inferred connections are empty, so HTTPS with no
// service_entries never becomes TCP/443 in the exported NetworkPolicy.
var wellKnownL4 = map[string]struct {
	protocol nsxgen.L4PortSetServiceEntryL4Protocol
	port     string
}{
	"HTTP":       {nsxgen.L4PortSetServiceEntryL4ProtocolTCP, "80"},
	"HTTPS":      {nsxgen.L4PortSetServiceEntryL4ProtocolTCP, "443"},
	"SSH":        {nsxgen.L4PortSetServiceEntryL4ProtocolTCP, "22"},
	"DNS":        {nsxgen.L4PortSetServiceEntryL4ProtocolUDP, "53"},
	"NTP":        {nsxgen.L4PortSetServiceEntryL4ProtocolUDP, "123"},
	"SMB":        {nsxgen.L4PortSetServiceEntryL4ProtocolTCP, "445"},
	"LDAP":       {nsxgen.L4PortSetServiceEntryL4ProtocolTCP, "389"},
	"LDAPS":      {nsxgen.L4PortSetServiceEntryL4ProtocolTCP, "636"},
	"RDP":        {nsxgen.L4PortSetServiceEntryL4ProtocolTCP, "3389"},
	"SQL":        {nsxgen.L4PortSetServiceEntryL4ProtocolTCP, "1433"},
	"MYSQL":      {nsxgen.L4PortSetServiceEntryL4ProtocolTCP, "3306"},
	"POSTGRESQL": {nsxgen.L4PortSetServiceEntryL4ProtocolTCP, "5432"},
	"REDIS":      {nsxgen.L4PortSetServiceEntryL4ProtocolTCP, "6379"},
}

// ensureResolvableServices makes named NSX services visible to vmware-analyzer's GetService
// (exact path match) and copies L4/ICMP entries onto each rule as a second path.
func ensureResolvableServices(resources *collector.ResourcesContainerModel) {
	if resources == nil {
		return
	}
	ensureServicePaths(resources)
	idx := buildServiceIndex(resources)
	flattenCatalogEntries(resources, idx)
	idx = buildServiceIndex(resources)
	injectMissingWellKnownServices(resources, idx)
	idx = buildServiceIndex(resources)
	aliasServicesForRulePaths(resources, idx)
	inlineResolvedServiceEntries(resources)
}

func ensureServicePaths(resources *collector.ResourcesContainerModel) {
	for i := range resources.ServiceList {
		svc := &resources.ServiceList[i]
		if svc.Path != nil && *svc.Path != "" {
			continue
		}
		name := stringOr(svc.Id, svc.DisplayName)
		if name == "" {
			continue
		}
		path := "/infra/services/" + name
		svc.Path = &path
	}
}

func flattenCatalogEntries(resources *collector.ResourcesContainerModel, idx serviceIndex) {
	for i := range resources.ServiceList {
		svc := &resources.ServiceList[i]
		visiting := map[string]bool{}
		if svc.Path != nil {
			visiting[*svc.Path] = true
		}
		flattened := flattenConnectableEntries(svc.ServiceEntries, idx, visiting)
		if len(flattened) > 0 {
			svc.ServiceEntries = flattened
			continue
		}
		if entry := wellKnownServiceEntry(stringOr(svc.DisplayName, svc.Id)); entry != nil {
			svc.ServiceEntries = collector.ServiceEntries{entry}
		}
	}
}

func injectMissingWellKnownServices(resources *collector.ResourcesContainerModel, idx serviceIndex) {
	needed := map[string]string{}
	for _, domain := range resources.DomainList {
		for _, policy := range domain.Resources.SecurityPolicyList {
			for _, rule := range policy.Rules {
				for _, path := range rule.Services {
					if isAnyService(path) || idx.lookup(path) != nil {
						continue
					}
					needed[path] = shortenPath(path)
				}
			}
		}
	}
	for path, name := range needed {
		entry := wellKnownServiceEntry(name)
		if entry == nil {
			continue
		}
		p, n := path, name
		resources.ServiceList = append(resources.ServiceList, collector.Service{
			Service: nsxgen.Service{
				DisplayName: &n,
				Id:          &n,
				Path:        &p,
			},
			ServiceEntries: collector.ServiceEntries{entry},
		})
	}
}

func aliasServicesForRulePaths(resources *collector.ResourcesContainerModel, idx serviceIndex) {
	have := map[string]bool{}
	for _, svc := range resources.ServiceList {
		if svc.Path != nil {
			have[*svc.Path] = true
		}
	}
	var aliases []collector.Service
	for _, domain := range resources.DomainList {
		for _, policy := range domain.Resources.SecurityPolicyList {
			for _, rule := range policy.Rules {
				for _, path := range rule.Services {
					if isAnyService(path) || have[path] {
						continue
					}
					svc := idx.lookup(path)
					if svc == nil {
						continue
					}
					clone := *svc
					p := path
					clone.Path = &p
					aliases = append(aliases, clone)
					have[path] = true
				}
			}
		}
	}
	resources.ServiceList = append(resources.ServiceList, aliases...)
}

func inlineResolvedServiceEntries(resources *collector.ResourcesContainerModel) {
	idx := buildServiceIndex(resources)
	for di := range resources.DomainList {
		policies := resources.DomainList[di].Resources.SecurityPolicyList
		for pi := range policies {
			for ri := range policies[pi].Rules {
				inlineRuleServices(&policies[pi].Rules[ri], idx)
			}
		}
	}
}

func inlineRuleServices(rule *collector.Rule, idx serviceIndex) {
	visiting := map[string]bool{}
	var extra collector.ServiceEntries

	for _, path := range rule.Services {
		if isAnyService(path) {
			continue
		}
		extra = append(extra, collectConnectableEntries(path, idx, visiting)...)
	}

	kept := make(collector.ServiceEntries, 0, len(rule.ServiceEntries)+len(extra))
	for _, entry := range rule.ServiceEntries {
		nested, ok := entry.(*collector.NestedServiceServiceEntry)
		if ok && nested.NestedServicePath != nil && *nested.NestedServicePath != "" {
			extra = append(extra, collectConnectableEntries(*nested.NestedServicePath, idx, visiting)...)
			continue
		}
		kept = append(kept, entry)
	}

	rule.ServiceEntries = append(kept, extra...)
}

func collectConnectableEntries(path string, idx serviceIndex, visiting map[string]bool) collector.ServiceEntries {
	key := strings.TrimSpace(path)
	if key == "" || visiting[key] {
		return nil
	}
	visiting[key] = true
	defer delete(visiting, key)

	svc := idx.lookup(key)
	if svc == nil {
		if entry := wellKnownServiceEntry(shortenPath(key)); entry != nil {
			return collector.ServiceEntries{entry}
		}
		return nil
	}
	if flattened := flattenConnectableEntries(svc.ServiceEntries, idx, visiting); len(flattened) > 0 {
		return flattened
	}
	if entry := wellKnownServiceEntry(stringOr(svc.DisplayName, svc.Id)); entry != nil {
		return collector.ServiceEntries{entry}
	}
	if entry := wellKnownServiceEntry(shortenPath(key)); entry != nil {
		return collector.ServiceEntries{entry}
	}
	return nil
}

func flattenConnectableEntries(entries collector.ServiceEntries, idx serviceIndex, visiting map[string]bool) collector.ServiceEntries {
	var out collector.ServiceEntries
	for _, entry := range entries {
		switch v := entry.(type) {
		case *collector.L4PortSetServiceEntry, *collector.ICMPTypeServiceEntry:
			out = append(out, entry)
		case *collector.NestedServiceServiceEntry:
			if v.NestedServicePath != nil && *v.NestedServicePath != "" {
				out = append(out, collectConnectableEntries(*v.NestedServicePath, idx, visiting)...)
			}
		}
	}
	return out
}

func wellKnownServiceEntry(name string) collector.ServiceEntry {
	spec, ok := wellKnownL4[strings.ToUpper(strings.TrimSpace(name))]
	if !ok {
		return nil
	}
	proto := spec.protocol
	rt := nsxgen.L4PortSetServiceEntryResourceTypeL4PortSetServiceEntry
	return &collector.L4PortSetServiceEntry{
		L4PortSetServiceEntry: nsxgen.L4PortSetServiceEntry{
			L4Protocol:       &proto,
			DestinationPorts: []nsxgen.PortElement{nsxgen.PortElement(spec.port)},
			ResourceType:     &rt,
		},
	}
}
