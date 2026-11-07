package trace

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

const sample = `100   execve("/usr/bin/pip", ["pip", "install", "requests"], 0x7ffd3c6e8a98 /* 20 vars */) = 0
100   clone3({flags=CLONE_VM|CLONE_VFORK, exit_signal=SIGCHLD, stack=0x7f1b4c7ff000, stack_size=0x9000}, 88) = 101
101   execve("/usr/bin/git", ["git", "clone", "https://github.com/psf/requests"...], 0x55d0 /* 20 vars */) = 0
101   clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|SIGCHLD, child_tidptr=0x7f) = 102
102   connect(3, {sa_family=AF_UNIX, sun_path="/var/run/nscd/socket"}, 110) = -1 ENOENT (No such file or directory)
102   connect(4, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.65.7")}, 16) = 0
102   connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("140.82.121.4")}, 16) = -1 EINPROGRESS (Operation now in progress)
100   connect(6, {sa_family=AF_INET6, sin6_port=htons(443), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, "2a04:4e42:400::223", &sin6_addr), sin6_scope_id=0}, 28) = 0
100   connect(7, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("151.101.1.223")}, 16) = -1 ENETUNREACH (Network is unreachable)
100   vfork( <unfinished ...>
100   <... vfork resumed>) = 103
101   clone(child_stack=0xffff9eeeea80, flags=CLONE_VM|CLONE_THREAD <unfinished ...>
101   <... clone resumed>, parent_tid=[104], tls=0xffff9eeef8c0, child_tidptr=0xffff9eeef5c8) = 104
104   connect(9, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("192.168.65.7")}, 16) = 0
103   connect(8, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("93.184.216.34")}, 16) = 0
100   +++ exited with 0 +++
`

func TestParse(t *testing.T) {
	l := Parse(strings.NewReader(sample))
	if got := l.Name(102); got != "git" {
		t.Errorf("Name(102) = %q, want git (inherited from 101)", got)
	}
	if got := l.Name(103); got != "pip" {
		t.Errorf("Name(103) = %q, want pip (vfork child, resumed line)", got)
	}
	if got := l.Owners(netip.MustParseAddr("140.82.121.4"), 443); !reflect.DeepEqual(got, []string{"git"}) {
		t.Errorf("Owners(github) = %v", got)
	}
	if got := l.Owners(netip.MustParseAddr("2a04:4e42:400::223"), 443); !reflect.DeepEqual(got, []string{"pip"}) {
		t.Errorf("Owners(v6) = %v", got)
	}
	if len(l.Conns) != 6 {
		t.Errorf("conns = %d, want 6 (AF_UNIX ignored)", len(l.Conns))
	}
	if got := l.Name(104); got != "git" {
		t.Errorf("Name(104) = %q, want git (thread created on a resumed clone line)", got)
	}
	failed := l.Failed()
	if len(failed) != 1 || failed[0].Errno != "ENETUNREACH" || failed[0].Addr != netip.MustParseAddr("151.101.1.223") {
		t.Errorf("failed = %+v", failed)
	}
	if l.Procs[100].Args != "pip install requests" {
		t.Errorf("args = %q", l.Procs[100].Args)
	}
}
