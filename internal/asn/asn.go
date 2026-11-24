// Package asn answers "whose network is this address in?" from the
// ip2asn database published by iptoasn.com (public domain), which maps
// address ranges to autonomous system number, country of registration and
// AS name. The file is downloaded once and cached.
package asn

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DefaultURL is the combined IPv4+IPv6 database.
const DefaultURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

// Info describes the network an address belongs to.
type Info struct {
	ASN     uint32
	Country string // ISO 3166-1 alpha-2 of the registration, "" when unrouted
	Name    string // AS description as registered, e.g. "FASTLY - Fastly, Inc."
}

// Org is a short display name for the operator.
func (i Info) Org() string {
	if i.ASN == 0 {
		return "not routed"
	}
	name := i.Name
	if _, after, ok := strings.Cut(name, " - "); ok && after != "" {
		name = after
	}
	for _, suf := range []string{", Inc.", ", Inc", " Inc.", " Inc", ", LLC", " LLC", " GmbH", " B.V.", " Ltd.", " Ltd", " S.A.", " Pty", " Co.,Ltd."} {
		name = strings.TrimSuffix(name, suf)
	}
	return strings.TrimSpace(name)
}

// Ranges are stored compactly: IPv4 bounds as integers, and the AS details
// interned in one table, because the database has ~700k rows but only ~80k
// distinct networks. This keeps a loaded database near 20 MB, small enough
// for a sidecar.
type r4 struct{ lo, hi, info uint32 }

type r6 struct {
	lo, hi netip.Addr
	info   uint32
}

// DB is a loaded database.
type DB struct {
	v4    []r4
	v6    []r6
	infos []Info
	// Updated is the modification time of the cached file.
	Updated time.Time
}

// CachePath is where the database is kept.
func CachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "buildtrace", "ip2asn-combined.tsv.gz")
}

// Download fetches the database into CachePath.
func Download(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "buildtrace (+https://github.com/officialasishkumar/buildtrace)")
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	path := CachePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Load reads the cached database, downloading it first when missing.
func Load(ctx context.Context) (*DB, error) {
	path := CachePath()
	st, err := os.Stat(path)
	if err != nil {
		if err := Download(ctx, DefaultURL); err != nil {
			return nil, fmt.Errorf("downloading the ip2asn database: %w", err)
		}
		if st, err = os.Stat(path); err != nil {
			return nil, err
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	db, err := Parse(f)
	if err != nil {
		return nil, err
	}
	db.Updated = st.ModTime()
	return db, nil
}

// Parse reads a gzip-compressed or plain ip2asn TSV.
func Parse(r io.Reader) (*DB, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	if head, err := br.Peek(2); err == nil && bytes.Equal(head, []byte{0x1f, 0x8b}) {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		br = bufio.NewReaderSize(gz, 1<<20)
	}
	db := &DB{v4: make([]r4, 0, 1<<19), v6: make([]r6, 0, 1<<18)}
	index := map[string]uint32{}
	sc := bufio.NewScanner(br)
	sc.Buffer(make([]byte, 1<<16), 1<<16)
	var f [5][]byte
	for sc.Scan() {
		line := sc.Bytes()
		n := 0
		for n < 4 {
			i := bytes.IndexByte(line, '\t')
			if i < 0 {
				break
			}
			f[n], line = line[:i], line[i+1:]
			n++
		}
		if n < 4 {
			continue
		}
		f[4] = line
		lo, err1 := netip.ParseAddr(string(f[0]))
		hi, err2 := netip.ParseAddr(string(f[1]))
		if err1 != nil || err2 != nil || lo.Is4() != hi.Is4() {
			continue
		}
		key := f[2:5]
		idx, ok := index[string(bytes.Join(key, []byte{'\t'}))]
		if !ok {
			asn, _ := strconv.ParseUint(string(f[2]), 10, 32)
			country := string(f[3])
			if country == "None" {
				country = ""
			}
			idx = uint32(len(db.infos))
			db.infos = append(db.infos, Info{ASN: uint32(asn), Country: country, Name: string(f[4])})
			index[string(bytes.Join(key, []byte{'\t'}))] = idx
		}
		if lo.Is4() {
			db.v4 = append(db.v4, r4{lo: v4int(lo), hi: v4int(hi), info: idx})
		} else {
			db.v6 = append(db.v6, r6{lo: lo, hi: hi, info: idx})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(db.v4, func(i, j int) bool { return db.v4[i].lo < db.v4[j].lo })
	sort.Slice(db.v6, func(i, j int) bool { return db.v6[i].lo.Less(db.v6[j].lo) })
	db.v4 = slices.Clip(db.v4)
	db.v6 = slices.Clip(db.v6)
	// Parsing churns through ~100 MB of short-lived strings; hand it back.
	debug.FreeOSMemory()
	return db, nil
}

func v4int(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// Lookup finds the network of addr. ok is false when the address is not in
// the database at all; a routed-but-unassigned range comes back with ASN 0.
func (db *DB) Lookup(addr netip.Addr) (Info, bool) {
	addr = addr.Unmap()
	if addr.Is4() {
		a := v4int(addr)
		i := sort.Search(len(db.v4), func(i int) bool { return a < db.v4[i].lo }) - 1
		if i < 0 || db.v4[i].hi < a {
			return Info{}, false
		}
		return db.infos[db.v4[i].info], true
	}
	i := sort.Search(len(db.v6), func(i int) bool { return addr.Less(db.v6[i].lo) }) - 1
	if i < 0 || db.v6[i].hi.Less(addr) {
		return Info{}, false
	}
	return db.infos[db.v6[i].info], true
}

// Len is the number of ranges loaded.
func (db *DB) Len() int { return len(db.v4) + len(db.v6) }
