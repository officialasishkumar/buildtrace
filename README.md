# buildtrace

Who does your build talk to?

`buildtrace run -- <command>` runs the command and prints every remote host it
contacted: the name (from DNS answers, TLS SNI or HTTP Host headers), the
network operator and its country of registration, bytes each way, and which
process in the build opened the connection.

```
$ buildtrace run -- zypper -n in --no-recommends vim

buildtrace: zypper -n in --no-recommends vim
exit 0 after 11.3s; 7 hosts, 14.1 MB down, 57 KB up

host                          port          flows    down     up  network                                               cc  process
mirrors.tuna.tsinghua.edu.cn  80/tcp plain      2  9.0 MB  23 KB  China Education and Research Network Center (AS4538)  CN  zypper
mirrors.nju.edu.cn            80/tcp plain      1  2.8 MB   5 KB  China Education and Research Network Center (AS4538)  CN  zypper
mirrors.bfsu.edu.cn           80/tcp plain      1  1.7 MB  16 KB  China Unicom Beijing Province Network (AS4808)        CN  zypper
ftp.sjtu.edu.cn               80/tcp plain      1  529 KB   8 KB  China Education and Research Network Center (AS4538)  CN  zypper
cdn.opensuse.org              80/tcp plain      1   21 KB   1 KB  Fastly (AS54113)                                      US  zypper
download.opensuse.org         80/tcp plain      6    4 KB   2 KB  SUSE SUSE Software Solutions Germany (AS29298)        DE  zypper
resolver 192.168.65.7         53/udp           18    4 KB   1 KB  resolver                                                  zypper
mirror.sjtu.edu.cn            80/tcp plain      1   536 B  535 B  China Education and Research Network Center (AS4538)  CN  zypper

by country of network registration: CN 100%, US 0%, DE 0%
by operator: China Education and Research Network Center 88%, China Unicom Beijing Province Network 12%, Fastly 0%, SUSE SUSE Software Solutions Germany 0%
DNS resolver: 192.168.65.7
7 host(s) were spoken to over plaintext HTTP
```

![buildtrace tracing zypper in vim](docs/buildtrace-zypper.svg)

That is a real run from a laptop in Asia: openSUSE's redirector in Germany
answered six times with 4 KB, and the 14 MB of packages came from four
university mirrors in China over plain HTTP. (RPM signatures keep the
packages trustworthy; the point is that nobody had told the person running
`zypper` where the bytes were coming from.)

```
$ buildtrace run -- pip install requests        # 100% Fastly (US): pypi.org, files.pythonhosted.org
$ buildtrace run -- go get github.com/spf13/cobra   # 100% Google (US): proxy.golang.org, sum.golang.org
```

## Why

Two audiences care about the same table.

- **Packagers.** Builds in the Open Build Service run without network access,
  so whatever an upstream build fetches has to be vendored. buildtrace shows
  exactly what `npm install`, `cargo build`, `go build` or a Makefile reaches
  for, before you find out from a failed OBS build.
- **People who have to answer sovereignty questions.** The existing
  self-assessment tools are questionnaires. buildtrace gives a measurement:
  for this build, these operators, in these countries, this many bytes,
  this much of it in plaintext. It does not decide whether that is acceptable;
  it makes the question answerable.

## How it works

1. A packet socket (AF_PACKET) in the current network namespace sees every
   IPv4/IPv6 packet the command and its children send or receive. No kernel
   modules, no eBPF, no root inside a container.
2. Flows are grouped by remote endpoint. Names come from DNS answers captured
   on the wire, from the SNI in TLS ClientHellos (reassembled across segments,
   so post-quantum-sized hellos work), and from HTTP Host headers.
3. `strace -f -e connect,execve,clone` runs the command and says which
   program opened each connection; children inherit their parent's name until
   they exec.
4. Each address is looked up in the iptoasn.com database (public domain,
   downloaded once to `~/.cache/buildtrace/`), giving the AS number, operator
   and country of registration.
5. `buildtrace offline -- <command>` reruns the command in an empty network
   namespace (`unshare -rn`) and lists every connection it tried, with the
   errno and the process. Exit 0 means the build works without the network.

## Install

```
go install github.com/officialasishkumar/buildtrace@latest
```

Linux only. It needs permission to open a packet socket: root, a container
(Docker and Podman grant `CAP_NET_RAW` by default; add `--cap-add SYS_PTRACE`
for the process column), or a user namespace. For a rootless setup on a
Tumbleweed host:

```
unshare -rn sh -c 'pasta --config-net -- buildtrace run -- make'   # pasta from the passt package
```

On a Mac, run it inside a Linux container.

## In Kubernetes: what does a pod fetch while it starts?

Every container in a pod shares one network namespace. Run `buildtrace
watch` as a [native sidecar](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)
(the first init container, with `restartPolicy: Always`, Kubernetes 1.29+)
and it is capturing before any other init container starts, so it sees the
whole boot: model weights, pip installs, licence checks, telemetry. The only
thing it cannot see is the image pull itself, which the node's runtime does
outside the pod (use [coldstart](https://github.com/officialasishkumar/coldstart)
for that).

```yaml
initContainers:
  - name: buildtrace
    image: ghcr.io/officialasishkumar/buildtrace:latest
    restartPolicy: Always
    args: ["watch", "--json", "/tmp/buildtrace.json", "--every", "5s"]
    securityContext:
      runAsUser: 0
      capabilities: { drop: ["ALL"], add: ["NET_RAW"] }
    resources:
      requests: { cpu: 50m, memory: 64Mi }
      limits: { memory: 128Mi }
  # ... your init containers and containers as before
```

Full example: [deploy/llm-pod-with-buildtrace.yaml](deploy/llm-pod-with-buildtrace.yaml),
a llama.cpp server whose init container downloads a 0.5B-parameter model.
On a kind cluster (Kubernetes 1.35, 24 Nov 2026):

```
$ kubectl exec llm-traced-gcj6x -c buildtrace -- /buildtrace show /tmp/buildtrace.json

buildtrace: watch llm-traced-gcj6x
recorded 50.0s; 2 hosts, 446.4 MB down, 428 KB up

host                 port     flows      down      up  network               cc     process
us.aws.cdn.hf.co     443/tcp      1  446.4 MB  425 KB  Amazon.com (AS16509)  US
huggingface.co       443/tcp      1      8 KB    2 KB  Amazon.com (AS16509)  US
resolver 10.96.0.10  53/udp       8      3 KB    1 KB  resolver              local

by country of network registration: US 100%
by operator: Amazon.com 100%
DNS resolver: 10.96.0.10
5 inbound connection(s) not listed (health checks, scrapes, clients)
```

Every byte of that model server's startup came from one US-registered
network, on every restart. Connections opened *to* the pod (kubelet probes,
Prometheus scrapes) are counted but not listed; in-cluster addresses are
labelled `private network`, so an in-cluster mirror shows up as exactly that.

The image is `FROM scratch` with the IP-to-network database baked in, so the
sidecar makes no connections of its own; it runs in under 64 MiB.

## Commands

```
buildtrace run [--json out.json] [--no-strace] [--no-lookup] -- <command>
buildtrace offline [--json out.json] -- <command>
buildtrace watch [--for DUR] [--json out.json] [--every DUR]
buildtrace show out.json
buildtrace update-db
```

## Limits, stated plainly

- "Country" is where the address block is registered, not where the server
  stands and not a legal opinion. A CDN registered in the US may serve you
  from a rack in Frankfurt. Treat the column as the start of a question.
- QUIC/HTTP3 traffic is counted but its SNI is not parsed; the name then
  comes from DNS.
- A host whose name was resolved before the trace started, or that is
  hard-coded as an address, shows up as an address.
- Under CPU emulation (an x86_64 container on an ARM Mac) strace cannot
  attach, so the process column stays empty. Use a native image.
- `offline` needs an unprivileged user namespace. Containers usually block
  it (run the container itself with `--network none`), and Ubuntu 24.04+
  restricts it through AppArmor (run as root there). Tumbleweed and Leap
  allow it.

## Related work

Each piece exists somewhere; the combination for a single command did not.

- **nsntrace** runs one command in a network namespace and writes a pcap for
  Wireshark. buildtrace keeps the command in its own namespace, parses the
  names itself and prints a table instead.
- **bandwhich** and **OpenSnitch** attribute live traffic to processes;
  **sniffnet** and **picosnitch** add ASN and country. All of them watch a
  machine over time rather than scoping a build and producing a report.
- **Harden-Runner** (StepSecurity) does the per-step egress report for GitHub
  Actions, as a hosted service. buildtrace is the local, any-command version.
- Build sandboxes enforce rather than report: build.opensuse.org workers run
  in secure mode with no network (the OBS User Guide warns that source
  services needing network "are likely to fail"), Fedora's mock disables
  networking by default, Debian's sbuild needs `--enable-network`. buildtrace
  tells you beforehand what such a build will miss, which is what the
  `obs-service-cargo`, `node_modules` and `go_modules` vendoring services
  then package.
- SUSE's Cloud Sovereignty Framework self-assessment (January 2026) is a
  32-question form in which supply chain carries 20% of the score. The form
  asks; this measures.

## License

MIT. The iptoasn.com data is public domain (CC0).
