// buildtrace records every remote host a build (or any command) talks to,
// who runs that host's network, and which process in the build did it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/officialasishkumar/buildtrace/internal/asn"
	"github.com/officialasishkumar/buildtrace/internal/capture"
	"github.com/officialasishkumar/buildtrace/internal/report"
	"github.com/officialasishkumar/buildtrace/internal/trace"
)

var version = "dev"

const usage = `buildtrace: who does your build talk to?

Usage:
  buildtrace run [flags] -- <command>      run the command, report every host it contacted
  buildtrace offline [flags] -- <command>  run it with no network and report what it tried to reach
  buildtrace show report.json              print a saved report
  buildtrace update-db                     refresh the IP-to-network database (iptoasn.com)
  buildtrace version

Flags for run:
  --json FILE      also write the full report as JSON
  --no-strace      do not attribute connections to processes (faster)
  --no-lookup      skip the network/country lookup (no database needed)
  --settle MS      wait this long after the command exits for trailing packets (default 500)

buildtrace needs Linux and permission to open a packet socket: root, a
container, or a user namespace (unshare -rn). On a Mac run it inside a
Linux container.

Example:
  buildtrace run --json pip.json -- pip install --no-cache-dir requests
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "buildtrace:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Print(usage)
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "run":
		return cmdRun(ctx, args[1:], false)
	case "offline":
		return cmdRun(ctx, args[1:], true)
	case "show":
		return cmdShow(args[1:])
	case "update-db":
		if err := asn.Download(ctx, asn.DefaultURL); err != nil {
			return err
		}
		db, err := asn.Load(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("%s: %d ranges\n", asn.CachePath(), db.Len())
		return nil
	case "version":
		fmt.Println("buildtrace", version)
		return nil
	}
	return fmt.Errorf("unknown command %q (try --help)", args[0])
}

func cmdShow(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: buildtrace show report.json")
	}
	b, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var r report.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return err
	}
	r.Text(os.Stdout)
	return nil
}

func cmdRun(ctx context.Context, args []string, offline bool) error {
	name := "run"
	if offline {
		name = "offline"
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	jsonOut := fs.String("json", "", "write the JSON report here")
	noStrace := fs.Bool("no-strace", false, "skip process attribution")
	noLookup := fs.Bool("no-lookup", false, "skip the network lookup")
	settle := fs.Int("settle", 500, "milliseconds to wait for trailing packets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cmd := fs.Args()
	if len(cmd) == 0 {
		return fmt.Errorf("usage: buildtrace %s [flags] -- <command>", name)
	}
	if offline {
		return runOffline(ctx, cmd, *jsonOut, !*noStrace)
	}
	if err := capture.Available(); err != nil {
		return err
	}
	useStrace := !*noStrace
	if useStrace && !trace.Available() {
		fmt.Fprintln(os.Stderr, "buildtrace: strace not found, connections will not be attributed to processes")
		useStrace = false
	}
	var db *asn.DB
	if !*noLookup {
		if _, err := os.Stat(asn.CachePath()); err != nil {
			fmt.Fprintf(os.Stderr, "buildtrace: downloading the IP-to-network database (about 11 MB, once) to %s\n", asn.CachePath())
		}
		var err error
		if db, err = asn.Load(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "buildtrace: no network lookup: %v\n", err)
		}
	}

	tr := capture.NewTracker()
	sniffCtx, stopSniff := context.WithCancel(context.Background())
	defer stopSniff()
	sniffErr := make(chan error, 1)
	go func() { sniffErr <- capture.Sniff(sniffCtx, tr) }()
	time.Sleep(150 * time.Millisecond)

	var straceFile string
	argv := cmd
	if useStrace {
		f, err := os.CreateTemp("", "buildtrace-strace-*.log")
		if err != nil {
			return err
		}
		straceFile = f.Name()
		f.Close()
		defer os.Remove(straceFile)
		argv = trace.Args(straceFile, cmd)
	}
	started := time.Now()
	exit, err := runChild(ctx, argv)
	dur := time.Since(started)
	if err != nil {
		return err
	}
	time.Sleep(time.Duration(*settle) * time.Millisecond)
	stopSniff()
	if serr := <-sniffErr; serr != nil {
		fmt.Fprintf(os.Stderr, "buildtrace: capture stopped early: %v\n", serr)
	}

	var tl *trace.Log
	if useStrace {
		if f, err := os.Open(straceFile); err == nil {
			tl = trace.Parse(f)
			f.Close()
		}
	}
	rep := report.Build(report.Inputs{Command: strings.Join(cmd, " "), Started: started, Duration: dur, ExitCode: exit,
		Hostname: capture.Hostname(), Packets: tr.Packets, Flows: tr.Flows(), Names: tr.Names, Resolver: tr.Resolvers(),
		DB: db, Trace: tl, Version: version})
	rep.Text(os.Stdout)
	if *jsonOut != "" {
		if err := writeJSON(*jsonOut, rep); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "report written to %s\n", *jsonOut)
	}
	if exit != 0 {
		os.Exit(exit)
	}
	return nil
}

// runChild runs argv with the terminal attached and returns its exit code.
func runChild(ctx context.Context, argv []string) (int, error) {
	c := exec.CommandContext(ctx, argv[0], argv[1:]...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	c.Cancel = func() error { return c.Process.Signal(syscall.SIGINT) }
	c.WaitDelay = 5 * time.Second
	err := c.Run()
	if err == nil {
		return 0, nil
	}
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		return ee.ExitCode(), nil
	}
	return -1, fmt.Errorf("starting %s: %w", argv[0], err)
}

// runOffline executes the command in a fresh network namespace with only
// loopback, so every outbound connection fails, and reports what it tried.
func runOffline(ctx context.Context, cmd []string, jsonOut string, useStrace bool) error {
	if _, err := exec.LookPath("unshare"); err != nil {
		return errors.New("offline mode needs unshare (util-linux)")
	}
	if out, err := exec.CommandContext(ctx, "unshare", "-rn", "true").CombinedOutput(); err != nil {
		return fmt.Errorf("cannot create a network namespace here (%s). Containers usually block this: run the container itself with --network none and use \"buildtrace run\" inside it. Ubuntu 24.04+ restricts unprivileged user namespaces through AppArmor: run as root there. openSUSE hosts allow it", strings.TrimSpace(string(out)))
	}
	inner := cmd
	var straceFile string
	if useStrace && trace.Available() {
		f, err := os.CreateTemp("", "buildtrace-strace-*.log")
		if err != nil {
			return err
		}
		straceFile = f.Name()
		f.Close()
		defer os.Remove(straceFile)
		inner = trace.Args(straceFile, cmd)
	}
	// -r maps the caller to root inside the namespace; -n gives a new, empty network namespace.
	argv := append([]string{"unshare", "-rn", "--", "sh", "-c", `ip link set lo up >/dev/null 2>&1; exec "$@"`, "buildtrace"}, inner...)
	started := time.Now()
	exit, err := runChild(ctx, argv)
	dur := time.Since(started)
	if err != nil {
		return err
	}
	rep := &report.Report{Command: strings.Join(cmd, " "), Started: started, DurationSec: dur.Seconds(), ExitCode: exit,
		Hostname: capture.Hostname(), GeneratedBy: "buildtrace " + version, Offline: &report.Offline{ExitCode: exit, DurationSec: dur.Seconds()}}
	if straceFile != "" {
		if f, err := os.Open(straceFile); err == nil {
			tl := trace.Parse(f)
			f.Close()
			for _, c := range tl.Failed() {
				rep.Offline.Attempts = append(rep.Offline.Attempts, report.Attempt{Process: tl.Name(c.PID), Addr: c.Addr.String(), Port: c.Port, Errno: c.Errno})
			}
		}
	}
	rep.Text(os.Stdout)
	if jsonOut != "" {
		return writeJSON(jsonOut, rep)
	}
	return nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
