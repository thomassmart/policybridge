package compare

import "testing"

func TestCompare_MissingConnection(t *testing.T) {
	nsx := []NSXConnection{
		{Source: "vm-a", Destination: "vm-c", Connections: "TCP dst-ports: 443"},
	}
	result := Compare(nsx, nil, nil)
	if result.Summary.Missing == 0 {
		t.Fatal("expected missing connections")
	}
}

func TestCompare_ICMPUncomparable(t *testing.T) {
	nsx := []NSXConnection{
		{Source: "vm-a", Destination: "vm-b", Connections: "ICMP"},
	}
	result := Compare(nsx, nil, nil)
	if result.Summary.Uncomparable == 0 {
		t.Fatal("expected ICMP to be uncomparable")
	}
}

func TestParseConnectionString(t *testing.T) {
	proto, ports := parseConnectionString("TCP dst-ports: 80,443")
	if proto != "TCP" || len(ports) != 2 {
		t.Fatalf("got proto=%s ports=%v", proto, ports)
	}

	proto, ports = parseConnectionString("All Connections")
	if proto != "ALL" || ports[0] != "all" {
		t.Fatalf("got proto=%s ports=%v", proto, ports)
	}
}

func TestParseNSXConnectivityFromText(t *testing.T) {
	text := `Analyzed connectivity:
Source         |Destination    |Permitted connections
vm-a           |vm-b           |TCP dst-ports: 80`
	conns := ParseNSXConnectivityFromText(text)
	if len(conns) != 1 {
		t.Fatalf("expected 1 connection, got %d", len(conns))
	}
	if conns[0].Source != "vm-a" {
		t.Fatalf("unexpected source: %s", conns[0].Source)
	}
}

func TestBuildLabelMap(t *testing.T) {
	m := BuildLabelMap([]string{"vm-a", "vm-b"})
	if m["vm-a"] != "vm-a" {
		t.Fatal("expected identity mapping")
	}
}

func TestParseNSXConnectivityJSON(t *testing.T) {
	conns := ParseNSXConnectivityJSON([]byte(`[{"src":"vm-a","dst":"vm-b","conn":"All Connections"}]`))
	if len(conns) != 1 || conns[0].Source != "vm-a" || conns[0].Connections != "All Connections" {
		t.Fatalf("unexpected parse: %#v", conns)
	}
}

func TestExpandUnrestricted(t *testing.T) {
	conns := []NSXConnection{
		{Source: "frontend-01", Destination: "backend-01", Connections: "All Connections"},
	}
	hints := []PortHint{
		{Sources: []string{"frontend"}, Destinations: []string{"backend"}, Protocol: "TCP", Ports: "443", RuleID: 7},
	}
	got := ExpandUnrestricted(conns, hints)
	if len(got) != 1 || got[0].Connections != "TCP dst-ports: 443" {
		t.Fatalf("expected expanded TCP/443, got %#v", got)
	}
}
