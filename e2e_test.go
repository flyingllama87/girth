package girth

import (
	"bytes"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// startTestServer launches a Server on an ephemeral TCP port serving dir, and
// returns its "host:port" address plus a stop func.
func startTestServer(t *testing.T, dir string, p TransferParams) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close() // reuse the chosen port

	srv := &Server{Addr: addr, Dir: dir, Params: p}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = srv.ListenAndServe(stop)
		close(done)
	}()
	// Wait for the listener to come up.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return addr, func() { close(stop); <-done }
}

func makeRandomFile(t *testing.T, path string, size int64) []byte {
	t.Helper()
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEndToEndPushPull(t *testing.T) {
	sizes := []int64{0, 1, 1500, 1 << 20, 5 << 20}
	srvDir := t.TempDir()
	cliDir := t.TempDir()

	p := DefaultParams()
	p.RateBps = 400_000_000
	p.ReportInterval = time.Hour // silence periodic reporter in tests

	addr, stop := startTestServer(t, srvDir, p)
	defer stop()

	for _, size := range sizes {
		name := "f" + strconv.FormatInt(size, 10) + ".bin"
		src := filepath.Join(cliDir, name)
		want := makeRandomFile(t, src, size)

		// PUSH: client -> server.
		if err := ClientSend(addr, src, p, nil); err != nil {
			t.Fatalf("push size=%d: %v", size, err)
		}
		got, err := os.ReadFile(filepath.Join(srvDir, name))
		if err != nil {
			t.Fatalf("push size=%d: read dest: %v", size, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("push size=%d: content mismatch (got %d want %d bytes)", size, len(got), len(want))
		}

		// PULL: server -> client.
		out := filepath.Join(cliDir, "pulled_"+name)
		if err := ClientRecv(addr, name, out, p, nil); err != nil {
			t.Fatalf("pull size=%d: %v", size, err)
		}
		got2, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("pull size=%d: read out: %v", size, err)
		}
		if !bytes.Equal(got2, want) {
			t.Fatalf("pull size=%d: content mismatch", size)
		}
	}
}

func TestEndToEndEncrypted(t *testing.T) {
	sizes := []int64{0, 1, 1500, 1 << 20, 5 << 20}
	srvDir := t.TempDir()
	cliDir := t.TempDir()

	p := DefaultParams()
	p.RateBps = 400_000_000
	p.Encrypt = true
	p.ReportInterval = time.Hour

	addr, stop := startTestServer(t, srvDir, p)
	defer stop()

	for _, size := range sizes {
		name := "enc" + strconv.FormatInt(size, 10) + ".bin"
		src := filepath.Join(cliDir, name)
		want := makeRandomFile(t, src, size)

		// PUSH (client encrypts -> server decrypts).
		if err := ClientSend(addr, src, p, nil); err != nil {
			t.Fatalf("encrypted push size=%d: %v", size, err)
		}
		got, err := os.ReadFile(filepath.Join(srvDir, name))
		if err != nil {
			t.Fatalf("encrypted push size=%d: read dest: %v", size, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("encrypted push size=%d: content mismatch", size)
		}

		// PULL (server encrypts -> client decrypts).
		out := filepath.Join(cliDir, "pulled_"+name)
		if err := ClientRecv(addr, name, out, p, nil); err != nil {
			t.Fatalf("encrypted pull size=%d: %v", size, err)
		}
		got2, err := os.ReadFile(out)
		if err != nil {
			t.Fatalf("encrypted pull size=%d: read out: %v", size, err)
		}
		if !bytes.Equal(got2, want) {
			t.Fatalf("encrypted pull size=%d: content mismatch", size)
		}
	}
}

// TestEndToEndPlaintextStillWorks: encryption is negotiated/optional, so a
// default (plaintext) transfer must keep working.
func TestEndToEndPlaintextStillWorks(t *testing.T) {
	srvDir := t.TempDir()
	cliDir := t.TempDir()
	p := DefaultParams()
	p.RateBps = 400_000_000
	p.ReportInterval = time.Hour
	addr, stop := startTestServer(t, srvDir, p)
	defer stop()

	src := filepath.Join(cliDir, "plain.bin")
	want := makeRandomFile(t, src, 2<<20)
	if err := ClientSend(addr, src, p, nil); err != nil {
		t.Fatalf("plaintext push: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(srvDir, "plain.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("plaintext push content mismatch")
	}
}

func TestEndToEndAdaptive(t *testing.T) {
	srvDir := t.TempDir()
	cliDir := t.TempDir()

	p := DefaultParams()
	p.Adaptive = true
	p.RateBps = 20_000_000
	p.MaxBps = 800_000_000
	p.AlphaBps = 50_000_000
	p.ReportInterval = time.Hour

	addr, stop := startTestServer(t, srvDir, p)
	defer stop()

	src := filepath.Join(cliDir, "adaptive.bin")
	want := makeRandomFile(t, src, 8<<20)
	if err := ClientSend(addr, src, p, nil); err != nil {
		t.Fatalf("adaptive push: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(srvDir, "adaptive.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("adaptive push content mismatch")
	}
}
