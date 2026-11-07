// Package trace attributes connections to processes using strace. Packet
// capture says which hosts were contacted; strace says which program in the
// build did it.
package trace

import (
	"bufio"
	"io"
	"net/netip"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Conn is one connect() call to an IP endpoint.
type Conn struct {
	PID   int
	Addr  netip.Addr
	Port  uint16
	Errno string // "" for success or EINPROGRESS
}

// Proc is one traced process.
type Proc struct {
	PID    int
	Parent int
	Comm   string // basename of the last executed program
	Args   string // its arguments, shortened
}

// Log is a parsed strace output.
type Log struct {
	Procs map[int]*Proc
	Conns []Conn
}

// Available reports whether strace can be used.
func Available() bool {
	_, err := exec.LookPath("strace")
	return err == nil
}

// Syscalls traced; clone/fork are needed to inherit names to children.
const Syscalls = "connect,execve,clone,clone3,vfork,fork"

// Args returns the strace command line that wraps cmd and writes to out.
func Args(out string, cmd []string) []string {
	a := []string{"strace", "-f", "-qq", "-e", "signal=none", "-e", "trace=" + Syscalls, "-s", "160", "-o", out, "--"}
	return append(a, cmd...)
}

var (
	execRe    = regexp.MustCompile(`^(\d+)\s+execve\("([^"]*)", \[(.*)\], `)
	cloneRe   = regexp.MustCompile(`^(\d+)\s+(?:<\.\.\. )?(?:clone3?|vfork|fork)\b.*\) = (\d+)\s*$`)
	connectRe = regexp.MustCompile(`^(\d+)\s+connect\(\d+, \{sa_family=AF_INET6?, sin6?_port=htons\((\d+)\), (?:sin_addr=inet_addr\("([^"]+)"\)|sin6_flowinfo=\w+\(\d+\), inet_pton\(AF_INET6, "([^"]+)")`)
	resultRe  = regexp.MustCompile(`\) = (-?\d+)(?: (E[A-Z0-9]+))?`)
)

// Parse reads strace -f output.
func Parse(r io.Reader) *Log {
	l := &Log{Procs: map[int]*Proc{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if m := execRe.FindStringSubmatch(line); m != nil {
			pid, _ := strconv.Atoi(m[1])
			p := l.proc(pid)
			p.Comm = path.Base(m[2])
			p.Args = shortenArgs(m[3])
			continue
		}
		if m := cloneRe.FindStringSubmatch(line); m != nil {
			parent, _ := strconv.Atoi(m[1])
			child, _ := strconv.Atoi(m[2])
			if child > 0 {
				l.proc(child).Parent = parent
				l.proc(parent)
			}
			continue
		}
		if m := connectRe.FindStringSubmatch(line); m != nil {
			pid, _ := strconv.Atoi(m[1])
			port, _ := strconv.Atoi(m[2])
			addrText := m[3]
			if addrText == "" {
				addrText = m[4]
			}
			addr, err := netip.ParseAddr(addrText)
			if err != nil {
				continue
			}
			c := Conn{PID: pid, Addr: addr.Unmap(), Port: uint16(port)}
			if rm := resultRe.FindStringSubmatch(line); rm != nil && rm[2] != "" && rm[2] != "EINPROGRESS" && rm[2] != "EALREADY" && rm[2] != "EISCONN" {
				c.Errno = rm[2]
			}
			l.proc(pid)
			l.Conns = append(l.Conns, c)
		}
	}
	_ = sc.Err() // strace output is a plain file; a read error only truncates attribution
	return l
}

func (l *Log) proc(pid int) *Proc {
	p := l.Procs[pid]
	if p == nil {
		p = &Proc{PID: pid}
		l.Procs[pid] = p
	}
	return p
}

// Name returns the program name for a pid, inherited from the nearest
// ancestor that executed something.
func (l *Log) Name(pid int) string {
	for range 64 {
		p := l.Procs[pid]
		if p == nil {
			return ""
		}
		if p.Comm != "" {
			return p.Comm
		}
		if p.Parent == 0 {
			return ""
		}
		pid = p.Parent
	}
	return ""
}

// Owners returns the distinct program names that connected to addr:port,
// successfully or not.
func (l *Log) Owners(addr netip.Addr, port uint16) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range l.Conns {
		if c.Addr == addr.Unmap() && c.Port == port {
			n := l.Name(c.PID)
			if n == "" {
				n = "pid " + strconv.Itoa(c.PID)
			}
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Failed lists connection attempts that failed, de-duplicated by endpoint.
func (l *Log) Failed() []Conn {
	seen := map[string]bool{}
	var out []Conn
	for _, c := range l.Conns {
		if c.Errno == "" || c.Addr.IsLoopback() {
			continue
		}
		k := c.Addr.String() + ":" + strconv.Itoa(int(c.Port)) + "/" + l.Name(c.PID)
		if !seen[k] {
			seen[k] = true
			out = append(out, c)
		}
	}
	return out
}

// shortenArgs turns strace's ["a", "b", ...] into `a b ...`, at most 80 chars.
func shortenArgs(s string) string {
	var parts []string
	for p := range strings.SplitSeq(s, `", "`) {
		p = strings.Trim(p, `"`)
		p = strings.TrimSuffix(p, `"...`)
		parts = append(parts, p)
	}
	out := strings.Join(parts, " ")
	if len(out) > 80 {
		out = out[:77] + "..."
	}
	return out
}
