package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/officialasishkumar/buildtrace/internal/asn"
	"github.com/officialasishkumar/buildtrace/internal/capture"
	"github.com/officialasishkumar/buildtrace/internal/report"
)

// cmdWatch records every flow in the current network namespace without
// running a command. Run as a Kubernetes native sidecar (an init container
// with restartPolicy: Always) it starts before the pod's other init
// containers and sees everything the pod fetches while it starts.
func cmdWatch(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	dur := fs.Duration("for", 0, "stop after this long")
	jsonOut := fs.String("json", "", "write the JSON report here")
	every := fs.Duration("every", 10*time.Second, "refresh the JSON report this often")
	noLookup := fs.Bool("no-lookup", false, "skip the network lookup")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := capture.Available(); err != nil {
		return err
	}
	if *dur > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *dur)
		defer cancel()
	}
	tr := capture.NewTracker()
	started := time.Now()
	sniffCtx, stopSniff := context.WithCancel(context.Background())
	defer stopSniff()
	sniffErr := make(chan error, 1)
	go func() { sniffErr <- capture.Sniff(sniffCtx, tr) }()
	fmt.Fprintf(os.Stderr, "buildtrace: watching %s\n", capture.Hostname())

	// The lookup database loads in the background so capture starts at once.
	dbc := make(chan *asn.DB, 1)
	go func() {
		if *noLookup {
			dbc <- nil
			return
		}
		db, err := asn.Load(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "buildtrace: no network lookup: %v\n", err)
		}
		dbc <- db
	}()
	var db *asn.DB
	dbReady := false
	build := func() *report.Report {
		if !dbReady {
			select {
			case db = <-dbc:
				dbReady = true
			default:
			}
		}
		return report.Build(report.Inputs{Command: "watch " + capture.Hostname(), Started: started, Duration: time.Since(started),
			Hostname: capture.Hostname(), Packets: tr.PacketCount(), Flows: tr.Flows(), Names: tr.Names, Resolver: tr.Resolvers(),
			DB: db, Version: version})
	}
	tick := time.NewTicker(*every)
	defer tick.Stop()
loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case err := <-sniffErr:
			if err != nil {
				fmt.Fprintf(os.Stderr, "buildtrace: capture stopped: %v\n", err)
			}
			break loop
		case <-tick.C:
			if *jsonOut != "" {
				if err := writeJSON(*jsonOut, build()); err != nil {
					fmt.Fprintf(os.Stderr, "buildtrace: %v\n", err)
				}
			}
		}
	}
	stopSniff()
	if !dbReady && !*noLookup {
		// Give a database that is still downloading a moment to finish.
		select {
		case db = <-dbc:
			dbReady = true
		case <-time.After(20 * time.Second):
		}
	}
	rep := build()
	rep.Text(os.Stdout)
	if *jsonOut != "" {
		return writeJSON(*jsonOut, rep)
	}
	return nil
}
