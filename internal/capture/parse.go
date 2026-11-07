// Package capture records which remote endpoints a process tree talks to
// while it runs, straight from the packets it sends and receives.
//
// The parsers in this file have no operating-system dependencies, so they
// are tested on any platform. The packet source lives in capture_linux.go.
package capture

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
)

// Packet is a decoded IP packet.
type Packet struct {
	Outgoing bool
	Proto    string // tcp or udp
	Src, Dst netip.Addr
	SrcPort  uint16
	DstPort  uint16
	Length   int    // IP packet length
	Payload  []byte // transport payload, nil for fragments and other protocols
	SYN      bool
}

// ParseIP decodes an IPv4 or IPv6 packet. ok is false for packets that are
// neither TCP nor UDP, or that are truncated.
func ParseIP(b []byte, outgoing bool) (p Packet, ok bool) {
	if len(b) < 20 {
		return p, false
	}
	p.Outgoing = outgoing
	var proto byte
	var payload []byte
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < 20 || total < ihl || len(b) < ihl {
			return p, false
		}
		if total > len(b) {
			total = len(b)
		}
		p.Length = total
		p.Src = netip.AddrFrom4([4]byte(b[12:16]))
		p.Dst = netip.AddrFrom4([4]byte(b[16:20]))
		proto = b[9]
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 { // later fragment
			return p, false
		}
		payload = b[ihl:total]
	case 6:
		if len(b) < 40 {
			return p, false
		}
		plen := int(binary.BigEndian.Uint16(b[4:6]))
		p.Length = 40 + plen
		p.Src = netip.AddrFrom16([16]byte(b[8:24]))
		p.Dst = netip.AddrFrom16([16]byte(b[24:40]))
		proto = b[6]
		payload = b[40:]
		if plen < len(payload) {
			payload = payload[:plen]
		}
		for {
			switch proto {
			case 0, 43, 60: // hop-by-hop, routing, destination options
				if len(payload) < 8 {
					return p, false
				}
				l := int(payload[1])*8 + 8
				if len(payload) < l {
					return p, false
				}
				proto, payload = payload[0], payload[l:]
				continue
			case 44: // fragment header: only the first fragment carries headers
				if len(payload) < 8 || binary.BigEndian.Uint16(payload[2:4])&0xfff8 != 0 {
					return p, false
				}
				proto, payload = payload[0], payload[8:]
				continue
			}
			break
		}
	default:
		return p, false
	}
	switch proto {
	case 6:
		if len(payload) < 20 {
			return p, false
		}
		off := int(payload[12]>>4) * 4
		if off < 20 || len(payload) < off {
			return p, false
		}
		p.Proto = "tcp"
		p.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		p.DstPort = binary.BigEndian.Uint16(payload[2:4])
		p.SYN = payload[13]&0x02 != 0 && payload[13]&0x10 == 0
		p.Payload = payload[off:]
	case 17:
		if len(payload) < 8 {
			return p, false
		}
		p.Proto = "udp"
		p.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		p.DstPort = binary.BigEndian.Uint16(payload[2:4])
		p.Payload = payload[8:]
	default:
		return p, false
	}
	return p, true
}

// DNSAnswer is one address record from a DNS response.
type DNSAnswer struct {
	Question string // the name that was asked for
	Name     string // the owner name of the record (after CNAMEs)
	Addr     netip.Addr
}

// ParseDNS extracts A and AAAA answers from a DNS message. Queries and
// malformed messages yield nothing.
func ParseDNS(msg []byte) (question string, answers []DNSAnswer) {
	if len(msg) < 12 {
		return "", nil
	}
	flags := binary.BigEndian.Uint16(msg[2:4])
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	off := 12
	for i := range qd {
		name, next, ok := readName(msg, off)
		if !ok || next+4 > len(msg) {
			return "", nil
		}
		if i == 0 {
			question = name
		}
		off = next + 4
	}
	if flags&0x8000 == 0 { // a query
		return question, nil
	}
	for range an {
		name, next, ok := readName(msg, off)
		if !ok || next+10 > len(msg) {
			break
		}
		typ := binary.BigEndian.Uint16(msg[next : next+2])
		rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rd := next + 10
		if rd+rdlen > len(msg) {
			break
		}
		switch {
		case typ == 1 && rdlen == 4:
			answers = append(answers, DNSAnswer{Question: question, Name: name, Addr: netip.AddrFrom4([4]byte(msg[rd : rd+4]))})
		case typ == 28 && rdlen == 16:
			answers = append(answers, DNSAnswer{Question: question, Name: name, Addr: netip.AddrFrom16([16]byte(msg[rd : rd+16]))})
		}
		off = rd + rdlen
	}
	return question, answers
}

// readName decodes a possibly compressed domain name starting at off and
// returns it with the offset just past it in the uncompressed stream.
func readName(msg []byte, off int) (string, int, bool) {
	var labels []string
	end := -1
	hops := 0
	for {
		if off >= len(msg) {
			return "", 0, false
		}
		l := int(msg[off])
		switch {
		case l == 0:
			off++
			if end < 0 {
				end = off
			}
			return strings.Join(labels, "."), end, true
		case l&0xc0 == 0xc0:
			if off+1 >= len(msg) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3fff)
			if end < 0 {
				end = off + 2
			}
			if hops++; hops > 64 || ptr >= len(msg) {
				return "", 0, false
			}
			off = ptr
		default:
			off++
			if off+l > len(msg) {
				return "", 0, false
			}
			labels = append(labels, string(msg[off:off+l]))
			off += l
		}
	}
}

// TLSServerName returns the SNI from a TLS ClientHello at the start of a
// stream. more is true when the record is longer than the bytes seen so
// far, i.e. the caller should try again with more data.
func TLSServerName(b []byte) (name string, more bool) {
	if len(b) < 5 || b[0] != 0x16 || b[1] != 0x03 {
		return "", false
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	if len(b) < 5+recLen {
		return "", recLen <= 1<<14
	}
	h := b[5 : 5+recLen]
	if len(h) < 4 || h[0] != 0x01 {
		return "", false
	}
	hl := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
	h = h[4:]
	if len(h) < hl {
		// ClientHello spans several records; parse what we have.
		hl = len(h)
	}
	h = h[:hl]
	pos := 2 + 32 // version + random
	if len(h) < pos+1 {
		return "", false
	}
	pos += 1 + int(h[pos]) // session id
	if len(h) < pos+2 {
		return "", false
	}
	pos += 2 + int(binary.BigEndian.Uint16(h[pos:pos+2])) // cipher suites
	if len(h) < pos+1 {
		return "", false
	}
	pos += 1 + int(h[pos]) // compression methods
	if len(h) < pos+2 {
		return "", false
	}
	extLen := int(binary.BigEndian.Uint16(h[pos : pos+2]))
	pos += 2
	end := min(pos+extLen, len(h))
	for pos+4 <= end {
		typ := binary.BigEndian.Uint16(h[pos : pos+2])
		l := int(binary.BigEndian.Uint16(h[pos+2 : pos+4]))
		pos += 4
		if pos+l > end {
			return "", false
		}
		if typ == 0 && l >= 5 {
			sni := h[pos : pos+l]
			nl := int(binary.BigEndian.Uint16(sni[3:5]))
			if sni[2] == 0 && 5+nl <= len(sni) {
				return string(sni[5 : 5+nl]), false
			}
		}
		pos += l
	}
	return "", false
}

var httpMethods = [][]byte{[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT ")}

// HTTPHost returns the Host header of a plaintext HTTP request at the start
// of a stream.
func HTTPHost(b []byte) string {
	isReq := false
	for _, m := range httpMethods {
		if bytes.HasPrefix(b, m) {
			isReq = true
			break
		}
	}
	if !isReq {
		return ""
	}
	headEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if headEnd < 0 {
		headEnd = len(b)
	}
	for line := range bytes.SplitSeq(b[:headEnd], []byte("\r\n")) {
		if len(line) > 5 && bytes.EqualFold(line[:5], []byte("host:")) {
			return strings.TrimSpace(string(line[5:]))
		}
	}
	return ""
}
