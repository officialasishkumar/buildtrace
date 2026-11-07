// Package report turns captured flows, DNS names, AS data and process
// attribution into the thing a person reads: who the build talked to.
package report

import (
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/officialasishkumar/buildtrace/internal/asn"
	"github.com/officialasishkumar/buildtrace/internal/capture"
	"github.com/officialasishkumar/buildtrace/internal/trace"
)

// Host is one remote service the build used: a name (or address), a port
// and a protocol, with everything observed about it.
type Host struct {
	Name      string   `json:"name"`
	NameFrom  string   `json:"name_from"` // sni, http, dns or ip
	Addrs     []string `json:"addrs"`
	Port      uint16   `json:"port"`
	Proto     string   `json:"proto"`
	Flows     int      `json:"flows"`
	BytesOut  int64    `json:"bytes_out"`
	BytesIn   int64    `json:"bytes_in"`
	ASN       uint32   `json:"asn,omitempty"`
	Org       string   `json:"org,omitempty"`
	ASName    string   `json:"as_name,omitempty"`
	Country   string   `json:"country,omitempty"`
	Processes []string `json:"processes,omitempty"`
	FirstSeen float64  `json:"first_seen_s"`
	Role      string   `json:"role,omitempty"` // dns, or empty
}

// Bucket aggregates bytes by country or organisation.
type Bucket struct {
	Key   string `json:"key"`
	Bytes int64  `json:"bytes"`
	Hosts int    `json:"hosts"`
}

// Attempt is a connection the build tried while offline.
type Attempt struct {
	Process string `json:"process"`
	Addr    string `json:"addr"`
	Port    uint16 `json:"port"`
	Errno   string `json:"errno"`
}

// Offline is the result of an offline run.
type Offline struct {
	ExitCode    int       `json:"exit_code"`
	DurationSec float64   `json:"duration_s"`
	Attempts    []Attempt `json:"attempts"`
}

// Report is the complete result of one traced command.
type Report struct {
	Command     string    `json:"command"`
	Started     time.Time `json:"started"`
	DurationSec float64   `json:"duration_s"`
	ExitCode    int       `json:"exit_code"`
	Hostname    string    `json:"hostname,omitempty"`
	Packets     int       `json:"packets"`
	Hosts       []Host    `json:"hosts"`
	Resolvers   []string  `json:"resolvers"`
	ByCountry   []Bucket  `json:"by_country"`
	ByOrg       []Bucket  `json:"by_org"`
	TotalIn     int64     `json:"bytes_in"`
	TotalOut    int64     `json:"bytes_out"`
	Unnamed     int       `json:"hosts_without_name"`
	Plaintext   int       `json:"plaintext_http_hosts"`
	DBUpdated   string    `json:"asn_db_updated,omitempty"`
	Traced      bool      `json:"process_attribution"`
	Offline     *Offline  `json:"offline,omitempty"`
	Notes       []string  `json:"notes,omitempty"`
	GeneratedBy string    `json:"generated_by"`
}

// Inputs is everything Build needs.
type Inputs struct {
	Command  string
	Started  time.Time
	Duration time.Duration
	ExitCode int
	Hostname string
	Packets  int
	Flows    []capture.Flow
	Names    func(netip.Addr) []string
	Resolver []netip.Addr
	DB       *asn.DB // may be nil
	Trace    *trace.Log
	Version  string
}

type agg struct {
	host  Host
	addrs map[string]bool
	bytes map[netip.Addr]int64
}

// Build assembles the report.
func Build(in Inputs) *Report {
	r := &Report{Command: in.Command, Started: in.Started, DurationSec: in.Duration.Seconds(), ExitCode: in.ExitCode,
		Hostname: in.Hostname, Packets: in.Packets, Traced: in.Trace != nil, GeneratedBy: "buildtrace " + in.Version}
	if in.DB != nil && !in.DB.Updated.IsZero() {
		r.DBUpdated = in.DB.Updated.Format("2006-01-02")
	}
	for _, a := range in.Resolver {
		r.Resolvers = append(r.Resolvers, a.String())
	}
	groups := map[string]*agg{}
	var order []string
	for _, f := range in.Flows {
		name, from := f.Server, f.ServerFrom
		if name == "" {
			if names := in.Names(f.Remote); len(names) > 0 {
				name, from = names[0], "dns"
			} else if f.RemotePort == 53 {
				name, from = f.Remote.String(), "resolver"
			} else {
				name, from = f.Remote.String(), "ip"
			}
		}
		key := fmt.Sprintf("%s|%d|%s", name, f.RemotePort, f.Proto)
		g := groups[key]
		if g == nil {
			g = &agg{host: Host{Name: name, NameFrom: from, Port: f.RemotePort, Proto: f.Proto, FirstSeen: f.First.Seconds()}, addrs: map[string]bool{}, bytes: map[netip.Addr]int64{}}
			if f.RemotePort == 53 {
				g.host.Role = "dns"
			}
			groups[key] = g
			order = append(order, key)
		}
		g.host.Flows++
		g.host.BytesIn += f.BytesIn
		g.host.BytesOut += f.BytesOut
		g.addrs[f.Remote.String()] = true
		g.bytes[f.Remote] += f.BytesIn + f.BytesOut
		if f.First.Seconds() < g.host.FirstSeen {
			g.host.FirstSeen = f.First.Seconds()
		}
	}
	country := map[string]*Bucket{}
	org := map[string]*Bucket{}
	for _, key := range order {
		g := groups[key]
		h := g.host
		for a := range g.addrs {
			h.Addrs = append(h.Addrs, a)
		}
		sort.Strings(h.Addrs)
		// Attribute the host to the network that carried most of its bytes.
		var top netip.Addr
		var topBytes int64 = -1
		for a, b := range g.bytes {
			if b > topBytes || (b == topBytes && a.Less(top)) {
				top, topBytes = a, b
			}
		}
		if in.DB != nil {
			if info, ok := in.DB.Lookup(top); ok {
				h.ASN, h.ASName, h.Country, h.Org = info.ASN, info.Name, info.Country, info.Org()
			}
		}
		if in.Trace != nil {
			seen := map[string]bool{}
			for a := range g.addrs {
				for _, p := range in.Trace.Owners(netip.MustParseAddr(a), h.Port) {
					if !seen[p] {
						seen[p] = true
						h.Processes = append(h.Processes, p)
					}
				}
			}
			sort.Strings(h.Processes)
		}
		if h.NameFrom == "ip" {
			r.Unnamed++
		}
		if h.NameFrom == "http" {
			r.Plaintext++
		}
		r.TotalIn += h.BytesIn
		r.TotalOut += h.BytesOut
		if h.Role != "dns" {
			bump(country, orUnknown(h.Country), h)
			bump(org, orUnknown(h.Org), h)
		}
		r.Hosts = append(r.Hosts, h)
	}
	sort.SliceStable(r.Hosts, func(i, j int) bool {
		return r.Hosts[i].BytesIn+r.Hosts[i].BytesOut > r.Hosts[j].BytesIn+r.Hosts[j].BytesOut
	})
	r.ByCountry = buckets(country)
	r.ByOrg = buckets(org)
	return r
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func bump(m map[string]*Bucket, key string, h Host) {
	b := m[key]
	if b == nil {
		b = &Bucket{Key: key}
		m[key] = b
	}
	b.Bytes += h.BytesIn + h.BytesOut
	b.Hosts++
}

func buckets(m map[string]*Bucket) []Bucket {
	var out []Bucket
	for _, b := range m {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Bytes != out[j].Bytes {
			return out[i].Bytes > out[j].Bytes
		}
		return out[i].Key < out[j].Key
	})
	return out
}

// Bytes formats a byte count for humans.
func Bytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// Text writes the human-readable report.
func (r *Report) Text(w io.Writer) {
	fmt.Fprintf(w, "\nbuildtrace: %s\n", r.Command)
	fmt.Fprintf(w, "exit %d after %.1fs; %d hosts, %s down, %s up\n", r.ExitCode, r.DurationSec, countNonDNS(r), Bytes(r.TotalIn), Bytes(r.TotalOut))
	if len(r.Hosts) == 0 && r.Offline == nil {
		fmt.Fprintln(w, "no network traffic observed")
	}
	if len(r.Hosts) > 0 {
		r.table(w)
	}
	for _, n := range r.Notes {
		fmt.Fprintln(w, n)
	}
	if r.Offline != nil {
		o := r.Offline
		fmt.Fprintf(w, "\noffline run: exit %d after %.1fs", o.ExitCode, o.DurationSec)
		if o.ExitCode == 0 {
			fmt.Fprintln(w, " — the command works without the network")
		} else {
			fmt.Fprintln(w, " — the command needs the network")
		}
		for _, a := range o.Attempts {
			fmt.Fprintf(w, "  %s tried %s:%d (%s)\n", a.Process, a.Addr, a.Port, a.Errno)
		}
	}
}

func (r *Report) table(w io.Writer) {
	head := []string{"host", "port", "flows", "down", "up", "network", "cc", "process"}
	var rows [][]string
	for _, h := range r.Hosts {
		net := h.Org
		if h.ASN != 0 {
			net = fmt.Sprintf("%s (AS%d)", h.Org, h.ASN)
		} else if h.Role == "dns" {
			net = "resolver"
		}
		name := h.Name
		if h.NameFrom == "ip" {
			name = h.Name + " (no name seen)"
		} else if h.NameFrom == "resolver" {
			name = "resolver " + h.Name
		} else if len(h.Addrs) > 1 {
			name = fmt.Sprintf("%s (%d addrs)", h.Name, len(h.Addrs))
		}
		proc := strings.Join(h.Processes, ",")
		if len(proc) > 24 {
			proc = proc[:21] + "..."
		}
		port := fmt.Sprintf("%d/%s", h.Port, h.Proto)
		if h.NameFrom == "http" {
			port += " plain"
		}
		rows = append(rows, []string{name, port, fmt.Sprint(h.Flows), Bytes(h.BytesIn), Bytes(h.BytesOut), net, h.Country, proc})
	}
	widths := make([]int, len(head))
	for i, c := range head {
		widths[i] = len(c)
	}
	for _, rw := range rows {
		for i, c := range rw {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	line := func(cells []string) {
		var b strings.Builder
		for i, c := range cells {
			if i > 0 {
				b.WriteString("  ")
			}
			pad := strings.Repeat(" ", widths[i]-len(c))
			if i == 2 || i == 3 || i == 4 {
				b.WriteString(pad)
				b.WriteString(c)
			} else {
				b.WriteString(c)
				b.WriteString(pad)
			}
		}
		fmt.Fprintln(w, strings.TrimRight(b.String(), " "))
	}
	fmt.Fprintln(w)
	line(head)
	for _, rw := range rows {
		line(rw)
	}
	fmt.Fprintln(w)
	if len(r.ByCountry) > 0 {
		fmt.Fprintf(w, "by country of network registration: %s\n", bucketLine(r.ByCountry, r.TotalIn+r.TotalOut))
	}
	if len(r.ByOrg) > 0 {
		fmt.Fprintf(w, "by operator: %s\n", bucketLine(r.ByOrg, r.TotalIn+r.TotalOut))
	}
	if len(r.Resolvers) > 0 {
		fmt.Fprintf(w, "DNS resolver: %s\n", strings.Join(r.Resolvers, ", "))
	}
	if r.Plaintext > 0 {
		fmt.Fprintf(w, "%d host(s) were spoken to over plaintext HTTP\n", r.Plaintext)
	}
	if r.Unnamed > 0 {
		fmt.Fprintf(w, "%d host(s) had no DNS name or SNI in the capture (hard-coded addresses, or resolved before the trace started)\n", r.Unnamed)
	}
	if !r.Traced {
		fmt.Fprintln(w, "process column empty: strace was not used")
	}
}

func countNonDNS(r *Report) int {
	n := 0
	for _, h := range r.Hosts {
		if h.Role != "dns" {
			n++
		}
	}
	return n
}

func bucketLine(bs []Bucket, total int64) string {
	var parts []string
	for i, b := range bs {
		if i == 6 {
			parts = append(parts, fmt.Sprintf("+%d more", len(bs)-i))
			break
		}
		pct := 0.0
		if total > 0 {
			pct = 100 * float64(b.Bytes) / float64(total)
		}
		parts = append(parts, fmt.Sprintf("%s %.0f%%", b.Key, pct))
	}
	return strings.Join(parts, ", ")
}
