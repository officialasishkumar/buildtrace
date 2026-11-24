package report

import (
	"net/netip"
	"testing"

	"github.com/officialasishkumar/buildtrace/internal/capture"
)

func TestBuildSkipsInboundAndLabelsPrivate(t *testing.T) {
	flows := []capture.Flow{
		{Proto: "tcp", Remote: netip.MustParseAddr("10.244.0.1"), RemotePort: 51864, LocalPort: 8080, BytesIn: 500, Inbound: true},
		{Proto: "tcp", Remote: netip.MustParseAddr("10.96.12.7"), RemotePort: 5000, BytesIn: 9000},
		{Proto: "tcp", Remote: netip.MustParseAddr("18.164.1.2"), RemotePort: 443, BytesIn: 1 << 20, Server: "cdn.example", ServerFrom: "sni"},
	}
	r := Build(Inputs{Command: "watch pod", Flows: flows, Names: func(netip.Addr) []string { return nil }})
	if r.Inbound != 1 || len(r.Hosts) != 2 {
		t.Fatalf("inbound=%d hosts=%d, want 1 and 2", r.Inbound, len(r.Hosts))
	}
	for _, h := range r.Hosts {
		if h.Name == "10.96.12.7" && (h.Org != "private network" || h.Country != "local") {
			t.Errorf("in-cluster host labelled %q/%q", h.Org, h.Country)
		}
	}
	if r.TotalIn != 1<<20+9000 {
		t.Errorf("TotalIn = %d", r.TotalIn)
	}
}
