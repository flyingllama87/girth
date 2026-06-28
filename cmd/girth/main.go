// Command girth is a CLI client/server for the girth bulk transfer protocol —
// a FASP-inspired reliable UDP file transfer designed for long fat networks
// (high bandwidth-delay product).
//
// Usage:
//
//	girth server [flags]                 start a server
//	girth send   [flags] <file> <host:port>      push file to server
//	girth recv   [flags] <host:port> <name> <out>  pull file from server
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"girth"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		cmdServer(os.Args[2:])
	case "send":
		cmdSend(os.Args[2:])
	case "recv":
		cmdRecv(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `girth — FASP-inspired LFN file transfer

commands:
  girth server [flags]                          run a server
  girth send   [flags] <file> <host:port>       push a file to a server
  girth recv   [flags] <host:port> <name> <out> pull a file from a server

run "girth <command> -h" for flags
`)
}

// commonFlags registers the tunables shared by all commands.
func commonFlags(fs *flag.FlagSet) (*girth.TransferParams, *int) {
	p := girth.DefaultParams()
	rateMbps := fs.Float64("rate", 100, "target injection rate (Mbps)")
	maxMbps := fs.Float64("max", 10000, "max injection rate (Mbps)")
	alphaMbps := fs.Float64("alpha", 30, "adaptive adaptation factor (Mbps)")
	fs.BoolVar(&p.Adaptive, "adaptive", false, "use delay-based adaptive rate control")
	fs.BoolVar(&p.Encrypt, "encrypt", false, "encrypt the data plane (X25519 + AES-GCM/ChaCha20-Poly1305)")
	fs.IntVar(&p.BlockSize, "block", girth.DefaultBlockSize, "UDP payload block size (bytes)")
	fs.IntVar(&p.ReadWorkers, "workers", 0, "disk/ingest worker goroutines (0=auto)")
	fs.IntVar(&p.FeedbackIntervalUs, "fb", 5000, "feedback/NACK interval (microseconds)")
	report := fs.Int("report", 1000, "stats report interval (ms; 0=off)")
	procs := fs.Int("procs", 0, "GOMAXPROCS (0=all cores)")

	// Float flags are resolved into the params struct after Parse.
	resolveFloats = func() {
		p.RateBps = uint64(*rateMbps * 1e6)
		p.MaxBps = uint64(*maxMbps * 1e6)
		p.AlphaBps = uint64(*alphaMbps * 1e6)
		if *report > 0 {
			p.ReportInterval = time.Duration(*report) * time.Millisecond
		} else {
			p.ReportInterval = time.Hour
		}
	}
	return &p, procs
}

var resolveFloats func()

func applyProcs(procs int) {
	if procs > 0 {
		runtime.GOMAXPROCS(procs)
	}
}

func sigStop() chan struct{} {
	stop := make(chan struct{})
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-ch
		close(stop)
	}()
	return stop
}

func cmdServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	addr := fs.String("addr", ":7400", "TCP control listen address")
	dir := fs.String("dir", ".", "directory to serve/store files")
	p, procs := commonFlags(fs)
	fs.Parse(args)
	resolveFloats()
	applyProcs(*procs)

	srv := &girth.Server{Addr: *addr, Dir: *dir, Params: *p}
	if err := srv.ListenAndServe(sigStop()); err != nil {
		fmt.Fprintln(os.Stderr, "server error:", err)
		os.Exit(1)
	}
}

func cmdSend(args []string) {
	fs := flag.NewFlagSet("send", flag.ExitOnError)
	p, procs := commonFlags(fs)
	fs.Parse(args)
	resolveFloats()
	applyProcs(*procs)

	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintln(os.Stderr, "usage: girth send [flags] <file> <host:port>")
		os.Exit(2)
	}
	if err := girth.ClientSend(rest[1], rest[0], *p, sigStop()); err != nil {
		fmt.Fprintln(os.Stderr, "send error:", err)
		os.Exit(1)
	}
}

func cmdRecv(args []string) {
	fs := flag.NewFlagSet("recv", flag.ExitOnError)
	p, procs := commonFlags(fs)
	fs.Parse(args)
	resolveFloats()
	applyProcs(*procs)

	rest := fs.Args()
	if len(rest) != 3 {
		fmt.Fprintln(os.Stderr, "usage: girth recv [flags] <host:port> <name> <out>")
		os.Exit(2)
	}
	if err := girth.ClientRecv(rest[0], rest[1], rest[2], *p, sigStop()); err != nil {
		fmt.Fprintln(os.Stderr, "recv error:", err)
		os.Exit(1)
	}
}
