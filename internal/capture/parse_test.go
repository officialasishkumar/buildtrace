package capture

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

func be16(v int) []byte { return []byte{byte(v >> 8), byte(v)} }

func dnsName(parts ...string) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, byte(len(p)))
		b = append(b, p...)
	}
	return append(b, 0)
}

func TestParseDNSResponseWithCompression(t *testing.T) {
	// Header: id, flags (response), qd=1, an=3, ns=0, ar=0
	msg := []byte{0x12, 0x34, 0x81, 0x80, 0, 1, 0, 3, 0, 0, 0, 0}
	msg = append(msg, dnsName("files", "pythonhosted", "org")...) // question at offset 12
	msg = append(msg, 0, 1, 0, 1)                                 // type A, class IN
	// CNAME files.pythonhosted.org -> dualstack.python.map.fastly.net
	msg = append(msg, 0xc0, 12)
	msg = append(msg, 0, 5, 0, 1, 0, 0, 0, 60)
	target := dnsName("dualstack", "python", "map", "fastly", "net")
	msg = append(msg, be16(len(target))...)
	cnameOff := len(msg)
	msg = append(msg, target...)
	// A record for the CNAME target (compressed pointer)
	msg = append(msg, 0xc0, byte(cnameOff))
	msg = append(msg, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 151, 101, 1, 223)
	// AAAA record
	msg = append(msg, 0xc0, byte(cnameOff))
	msg = append(msg, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16)
	v6 := netip.MustParseAddr("2a04:4e42:400::223").As16()
	msg = append(msg, v6[:]...)

	q, answers := ParseDNS(msg)
	if q != "files.pythonhosted.org" {
		t.Errorf("question = %q", q)
	}
	if len(answers) != 2 {
		t.Fatalf("answers = %+v", answers)
	}
	if answers[0].Addr != netip.MustParseAddr("151.101.1.223") || answers[0].Name != "dualstack.python.map.fastly.net" || answers[0].Question != q {
		t.Errorf("A = %+v", answers[0])
	}
	if answers[1].Addr != netip.MustParseAddr("2a04:4e42:400::223") {
		t.Errorf("AAAA = %+v", answers[1])
	}
	// A query (QR=0) yields the question but no answers.
	query := append([]byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}, dnsName("pypi", "org")...)
	query = append(query, 0, 1, 0, 1)
	if q, a := ParseDNS(query); q != "pypi.org" || a != nil {
		t.Errorf("query: %q %v", q, a)
	}
	// Pointer loop must not hang.
	loop := append([]byte{0, 0, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}, 0xc0, 12)
	ParseDNS(loop)
}

func clientHello(sni string, pad int) []byte {
	var hello []byte
	hello = append(hello, 3, 3)                // version
	hello = append(hello, make([]byte, 32)...) // random
	hello = append(hello, 0)                   // session id
	hello = append(hello, 0, 2, 0x13, 0x01)    // one cipher suite
	hello = append(hello, 1, 0)                // compression
	var ext []byte
	name := []byte(sni)
	sniExt := append(be16(len(name)+3), 0)
	sniExt = append(sniExt, be16(len(name))...)
	sniExt = append(sniExt, name...)
	ext = append(ext, 0, 0)
	ext = append(ext, be16(len(sniExt))...)
	ext = append(ext, sniExt...)
	if pad > 0 { // a key_share-like big extension after SNI
		ext = append(ext, 0, 51)
		ext = append(ext, be16(pad)...)
		ext = append(ext, make([]byte, pad)...)
	}
	hello = append(hello, be16(len(ext))...)
	hello = append(hello, ext...)
	hs := []byte{1, byte(len(hello) >> 16), byte(len(hello) >> 8), byte(len(hello))}
	hs = append(hs, hello...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = append(rec, be16(len(hs))...)
	return append(rec, hs...)
}

func TestTLSServerName(t *testing.T) {
	ch := clientHello("pypi.org", 0)
	if name, more := TLSServerName(ch); name != "pypi.org" || more {
		t.Errorf("got %q more=%v", name, more)
	}
	// Large ClientHello delivered in two segments: first segment is incomplete.
	big := clientHello("static.crates.io", 1800)
	if name, more := TLSServerName(big[:1400]); name != "" || !more {
		t.Errorf("partial: got %q more=%v, want more", name, more)
	}
	if name, _ := TLSServerName(big); name != "static.crates.io" {
		t.Errorf("full: got %q", name)
	}
	if name, more := TLSServerName([]byte("GET / HTTP/1.1\r\n")); name != "" || more {
		t.Errorf("non-TLS: %q %v", name, more)
	}
}

func TestHTTPHost(t *testing.T) {
	if h := HTTPHost([]byte("GET /tumbleweed/repo/oss/repodata/repomd.xml HTTP/1.1\r\nUser-Agent: ZYpp\r\nHost: download.opensuse.org\r\nAccept: */*\r\n\r\n")); h != "download.opensuse.org" {
		t.Errorf("host = %q", h)
	}
	if h := HTTPHost([]byte("\x16\x03\x01")); h != "" {
		t.Errorf("tls as http: %q", h)
	}
}

func TestParseIPv4TCP(t *testing.T) {
	payload := []byte("GET / HTTP/1.1\r\nHost: example.org\r\n\r\n")
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 40000)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	tcp[12] = 5 << 4
	tcp[13] = 0x18 // PSH|ACK
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	ip[9] = 6
	copy(ip[12:16], []byte{10, 0, 2, 15})
	copy(ip[16:20], []byte{93, 184, 216, 34})
	pkt := append(append(ip, tcp...), payload...)
	p, ok := ParseIP(pkt, true)
	if !ok || p.Proto != "tcp" || p.DstPort != 80 || p.Dst != netip.MustParseAddr("93.184.216.34") || string(p.Payload) != string(payload) || p.Length != len(pkt) {
		t.Errorf("parsed %+v ok=%v", p, ok)
	}
	tr := NewTracker()
	tr.Handle(p, true)
	flows := tr.Flows()
	if len(flows) != 1 || flows[0].Server != "example.org" || flows[0].BytesOut != int64(len(pkt)) {
		t.Errorf("flows = %+v", flows)
	}
}
