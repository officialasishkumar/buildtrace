package capture

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

const headLimit = 8192

// Flow is one transport connection (or UDP exchange) with a remote endpoint.
type Flow struct {
	Proto      string
	Remote     netip.Addr
	RemotePort uint16
	LocalPort  uint16
	BytesOut   int64
	BytesIn    int64
	Packets    int
	First      time.Duration // since tracking started
	Server     string        // from TLS SNI or an HTTP Host header
	ServerFrom string        // "sni" or "http"
	head       []byte
	headDone   bool
}

type flowKey struct {
	proto      string
	remote     netip.Addr
	remotePort uint16
	localPort  uint16
}

// Tracker aggregates packets into flows and learns names from DNS answers.
type Tracker struct {
	mu        sync.Mutex
	start     time.Time
	flows     map[flowKey]*Flow
	names     map[netip.Addr]map[string]bool
	resolvers map[netip.Addr]bool
	Packets   int
}

// NewTracker starts the clock.
func NewTracker() *Tracker {
	return &Tracker{start: time.Now(), flows: map[flowKey]*Flow{}, names: map[netip.Addr]map[string]bool{}, resolvers: map[netip.Addr]bool{}}
}

// Handle accounts one packet. count is false for interfaces whose traffic
// should only be mined for DNS answers (loopback), not reported as flows.
func (t *Tracker) Handle(p Packet, count bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Packets++
	remote, rport, lport := p.Dst, p.DstPort, p.SrcPort
	if !p.Outgoing {
		remote, rport, lport = p.Src, p.SrcPort, p.DstPort
	}
	if p.Proto == "udp" && (p.DstPort == 53 || p.SrcPort == 53) {
		if !p.Outgoing && p.SrcPort == 53 {
			_, answers := ParseDNS(p.Payload)
			for _, a := range answers {
				if t.names[a.Addr] == nil {
					t.names[a.Addr] = map[string]bool{}
				}
				t.names[a.Addr][a.Question] = true
			}
		}
		if count {
			t.resolvers[remote] = true
		}
	}
	if !count || remote.IsLoopback() {
		return
	}
	k := flowKey{p.Proto, remote.Unmap(), rport, lport}
	f := t.flows[k]
	if f == nil {
		f = &Flow{Proto: p.Proto, Remote: remote.Unmap(), RemotePort: rport, LocalPort: lport, First: time.Since(t.start)}
		t.flows[k] = f
	}
	f.Packets++
	if p.Outgoing {
		f.BytesOut += int64(p.Length)
	} else {
		f.BytesIn += int64(p.Length)
	}
	if p.Proto == "tcp" && p.Outgoing && !f.headDone && len(p.Payload) > 0 {
		f.head = append(f.head, p.Payload...)
		if name, more := TLSServerName(f.head); name != "" {
			f.Server, f.ServerFrom, f.headDone = name, "sni", true
		} else if !more {
			if h := HTTPHost(f.head); h != "" {
				f.Server, f.ServerFrom = h, "http"
			}
			f.headDone = true
		}
		if len(f.head) >= headLimit {
			f.headDone = true
		}
		if f.headDone {
			f.head = nil
		}
	}
}

// Flows returns a snapshot of all flows, oldest first.
func (t *Tracker) Flows() []Flow {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Flow, 0, len(t.flows))
	for _, f := range t.flows {
		c := *f
		c.head = nil
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].First < out[j].First })
	return out
}

// Names returns the DNS names that resolved to addr during the capture.
func (t *Tracker) Names(addr netip.Addr) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for n := range t.names[addr.Unmap()] {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Resolvers returns the DNS servers that were queried.
func (t *Tracker) Resolvers() []netip.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []netip.Addr
	for r := range t.resolvers {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}
