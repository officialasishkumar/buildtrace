package asn

import (
	"net/netip"
	"strings"
	"testing"
)

const sample = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET - Cloudflare, Inc.\n" +
	"1.0.4.0\t1.0.7.255\t38803\tAU\tWPL-AS-AP Wirefreebroadband Pty Ltd\n" +
	"1.0.8.0\t1.0.15.255\t0\tNone\tNot routed\n" +
	"151.101.0.0\t151.101.255.255\t54113\tUS\tFASTLY - Fastly, Inc.\n" +
	"2a04:4e40::\t2a04:4e47:ffff:ffff:ffff:ffff:ffff:ffff\t54113\tUS\tFASTLY - Fastly, Inc.\n" +
	"bad line\n"

func TestParseAndLookup(t *testing.T) {
	db, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	if db.Len() != 5 || len(db.infos) != 4 {
		t.Fatalf("len=%d infos=%d, want 5 ranges sharing 4 networks", db.Len(), len(db.infos))
	}
	cases := []struct {
		addr    string
		ok      bool
		asn     uint32
		org, cc string
	}{
		{"1.0.0.1", true, 13335, "Cloudflare", "US"},
		{"1.0.0.255", true, 13335, "Cloudflare", "US"},
		{"1.0.1.0", false, 0, "", ""},
		{"1.0.9.9", true, 0, "not routed", ""},
		{"151.101.1.69", true, 54113, "Fastly", "US"},
		{"::ffff:151.101.1.69", true, 54113, "Fastly", "US"},
		{"2a04:4e42::1", true, 54113, "Fastly", "US"},
		{"2a05::1", false, 0, "", ""},
		{"0.0.0.1", false, 0, "", ""},
	}
	for _, c := range cases {
		info, ok := db.Lookup(netip.MustParseAddr(c.addr))
		if ok != c.ok || info.ASN != c.asn || (ok && (info.Org() != c.org || info.Country != c.cc)) {
			t.Errorf("%s: got %+v ok=%v org=%q", c.addr, info, ok, info.Org())
		}
	}
}
