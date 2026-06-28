package girth

import (
	"crypto/ecdh"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"time"
)

func numBlocks(size int64, blockSize int) uint64 {
	if size <= 0 {
		return 0
	}
	return uint64((size + int64(blockSize) - 1) / int64(blockSize))
}

// prepareDestFile sizes the receive file to size. It uses fallocate to allocate
// real blocks rather than leaving a sparse file: under loss the receiver writes
// blocks at scattered offsets (retransmits), and on a sparse file every such
// write triggers on-the-fly block allocation plus sub-page read-modify-write —
// slow random I/O that blocks the ingest goroutines and overflows the UDP
// socket (a loss storm). A pre-allocated file turns those into plain overwrites.
// Falls back to Truncate if fallocate is unsupported (e.g. tmpfs).
func prepareDestFile(f *os.File, size int64) error {
	if size > 0 {
		if err := platformFallocate(f, size); err == nil {
			return nil
		}
	}
	return f.Truncate(size)
}

// newUDPSocket binds an ephemeral (or specified) UDP socket with enlarged
// kernel buffers — essential for high-BDP LFN paths so the OS can hold a full
// window of in-flight packets without dropping.
func newUDPSocket(port int) (*net.UDPConn, error) {
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return nil, err
	}
	// Large kernel buffers are essential on a high-BDP LFN path: the receive
	// buffer must absorb bursts (path queue dumps, scheduling jitter) without
	// dropping, since UDP has no flow control. Best-effort; capped by
	// net.core.{r,w}mem_max.
	_ = c.SetReadBuffer(64 << 20)
	_ = c.SetWriteBuffer(64 << 20)
	return c, nil
}

func udpPortOf(c *net.UDPConn) int { return c.LocalAddr().(*net.UDPAddr).Port }

// ClientSend pushes localPath to the girth server at serverAddr (host:port).
func ClientSend(serverAddr, localPath string, p TransferParams, stop <-chan struct{}) error {
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	crc, err := fileCRC32C(f)
	if err != nil {
		return err
	}

	tcp, err := net.DialTimeout("tcp", serverAddr, 15*time.Second)
	if err != nil {
		return err
	}
	defer tcp.Close()

	var priv *ecdh.PrivateKey
	var pub []byte
	if p.Encrypt {
		if priv, pub, err = genKeypair(); err != nil {
			return err
		}
	}
	if err := writeJSON(tcp, hello{
		Version: ProtocolVersion, Mode: ModeSend, Name: basename(localPath),
		Size: fi.Size(), BlockSize: p.BlockSize, RateBps: p.RateBps,
		MaxBps: p.MaxBps, Adaptive: p.Adaptive, AlphaBps: p.AlphaBps, CRC32C: crc,
		Encrypt: p.Encrypt, Ciphers: ciphersIf(p.Encrypt), PubKey: pub,
	}); err != nil {
		return err
	}
	var a ack
	if err := readJSON(tcp, &a); err != nil {
		return err
	}
	if !a.OK {
		return fmt.Errorf("server rejected transfer: %s", a.Err)
	}
	box, err := clientCrypto(p.Encrypt, a, priv)
	if err != nil {
		return err
	}

	host, _, _ := net.SplitHostPort(serverAddr)
	peer := &net.UDPAddr{IP: net.ParseIP(host), Port: a.UDPPort}
	if peer.IP == nil {
		ips, _ := net.LookupIP(host)
		if len(ips) > 0 {
			peer.IP = ips[0]
		}
	}
	conn, err := newUDPSocket(0)
	if err != nil {
		return err
	}
	defer conn.Close()

	stats := NewStats()
	logw := os.Stderr
	rs := make(chan struct{})
	go stats.Reporter(logw, "send", p.ReportInterval, rs)
	defer close(rs)

	snd := NewSender(SendConfig{
		Conn: conn, Peer: peer, File: f, FileSize: fi.Size(),
		BlockSize: p.BlockSize, TotalBlocks: numBlocks(fi.Size(), p.BlockSize),
		Session: a.Session, Rate: p.rateConfig(p.RateBps),
		ReadWorkers: p.ReadWorkers, Crypto: box, Stats: stats,
		Log: log.New(logw, "girth-send ", log.LstdFlags|log.Lmicroseconds),
	})
	start := time.Now()
	if err := snd.Run(stop); err != nil {
		return err
	}
	_ = start
	fmt.Fprintln(logw, stats.Summary("send"))
	return nil
}

// ClientRecv pulls remoteName from the server into outPath.
func ClientRecv(serverAddr, remoteName, outPath string, p TransferParams, stop <-chan struct{}) error {
	tcp, err := net.DialTimeout("tcp", serverAddr, 15*time.Second)
	if err != nil {
		return err
	}
	defer tcp.Close()

	var priv *ecdh.PrivateKey
	var pub []byte
	if p.Encrypt {
		if priv, pub, err = genKeypair(); err != nil {
			return err
		}
	}
	if err := writeJSON(tcp, hello{
		Version: ProtocolVersion, Mode: ModeRecv, Name: remoteName,
		BlockSize: p.BlockSize, RateBps: p.RateBps, MaxBps: p.MaxBps, Adaptive: p.Adaptive, AlphaBps: p.AlphaBps,
		Encrypt: p.Encrypt, Ciphers: ciphersIf(p.Encrypt), PubKey: pub,
	}); err != nil {
		return err
	}
	var a ack
	if err := readJSON(tcp, &a); err != nil {
		return err
	}
	if !a.OK {
		return fmt.Errorf("server rejected transfer: %s", a.Err)
	}
	box, err := clientCrypto(p.Encrypt, a, priv)
	if err != nil {
		return err
	}

	if outPath == "" || isDir(outPath) {
		outPath = filepath.Join(outPath, basename(remoteName))
	}
	f, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := prepareDestFile(f, a.Size); err != nil {
		return err
	}

	host, _, _ := net.SplitHostPort(serverAddr)
	peer := &net.UDPAddr{IP: net.ParseIP(host), Port: a.UDPPort}
	if peer.IP == nil {
		ips, _ := net.LookupIP(host)
		if len(ips) > 0 {
			peer.IP = ips[0]
		}
	}
	conn, err := newUDPSocket(0)
	if err != nil {
		return err
	}
	defer conn.Close()

	// Send START so the server (sender) learns our UDP address.
	var sb [8]byte
	n := encodeStart(sb[:], a.Session)
	for i := 0; i < 5; i++ {
		_, _ = conn.WriteToUDP(sb[:n], peer)
	}

	stats := NewStats()
	logw := os.Stderr
	rs := make(chan struct{})
	go stats.Reporter(logw, "recv", p.ReportInterval, rs)
	defer close(rs)

	rcv := NewReceiver(RecvConfig{
		Conn: conn, File: f, FileSize: a.Size,
		BlockSize: p.BlockSize, TotalBlocks: numBlocks(a.Size, p.BlockSize),
		Session: a.Session, ReadWorkers: p.ReadWorkers,
		Rate:               p.rateConfig(p.RateBps),
		Crypto:             box,
		FeedbackIntervalUs: p.FeedbackIntervalUs, NetTickIntervalUs: p.NetTickIntervalUs,
		Stats: stats,
		Log:   log.New(logw, "girth-recv ", log.LstdFlags|log.Lmicroseconds),
	})
	// Keep nudging START until data starts flowing.
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		for i := 0; i < 25; i++ {
			select {
			case <-stop:
				return
			case <-t.C:
				if stats.PacketsRecv.Load() > 0 {
					return
				}
				_, _ = conn.WriteToUDP(sb[:n], peer)
			}
		}
	}()
	if err := rcv.Run(stop); err != nil {
		return err
	}
	fmt.Fprintln(logw, stats.Summary("recv"))

	if got, err := fileCRC32C(f); err == nil {
		if got != a.CRC32C {
			return fmt.Errorf("INTEGRITY FAILURE: crc32c got=%08x want=%08x", got, a.CRC32C)
		}
		fmt.Fprintf(logw, "integrity OK (crc32c=%08x)\n", got)
	}
	return nil
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// Server accepts control connections and runs the negotiated transfers.
type Server struct {
	Addr   string // TCP listen addr
	Dir    string // root dir for serving (recv) and storing (send) files
	Params TransferParams
	Log    *log.Logger
}

// ListenAndServe runs until stop is closed.
func (s *Server) ListenAndServe(stop <-chan struct{}) error {
	if s.Log == nil {
		s.Log = log.New(os.Stderr, "girth-srv ", log.LstdFlags)
	}
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	s.Log.Printf("listening on %s (control/TCP), serving dir %s", ln.Addr(), s.Dir)

	go func() { <-stop; ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			select {
			case <-stop:
				return nil
			default:
				return err
			}
		}
		go s.handle(c, stop)
	}
}

func (s *Server) handle(c net.Conn, stop <-chan struct{}) {
	defer c.Close()
	defer func() {
		if r := recover(); r != nil {
			s.Log.Printf("transfer panic from %s: %v", c.RemoteAddr(), r)
		}
	}()
	var h hello
	if err := readJSON(c, &h); err != nil {
		s.Log.Printf("handshake read error from %s: %v", c.RemoteAddr(), err)
		return
	}
	if h.Version != ProtocolVersion {
		_ = writeJSON(c, ack{Err: "protocol version mismatch"})
		return
	}
	if h.BlockSize <= 0 {
		h.BlockSize = s.Params.BlockSize
	}
	session := rand.Uint32()
	p := s.Params
	p.BlockSize = h.BlockSize
	p.Adaptive = h.Adaptive
	if h.AlphaBps > 0 {
		p.AlphaBps = h.AlphaBps
	}
	if h.RateBps > 0 {
		p.RateBps = h.RateBps
	}
	if h.MaxBps > 0 {
		p.MaxBps = h.MaxBps
	}

	switch h.Mode {
	case ModeSend:
		s.recvFromClient(c, h, session, p, stop)
	case ModeRecv:
		s.sendToClient(c, h, session, p, stop)
	default:
		_ = writeJSON(c, ack{Err: "unknown mode"})
	}
}

// recvFromClient: client pushes a file; server is the data receiver.
func (s *Server) recvFromClient(c net.Conn, h hello, session uint32, p TransferParams, stop <-chan struct{}) {
	outPath := filepath.Join(s.Dir, filepath.Base(h.Name))
	f, err := os.OpenFile(outPath, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		_ = writeJSON(c, ack{Err: err.Error()})
		return
	}
	defer f.Close()
	if err := prepareDestFile(f, h.Size); err != nil {
		_ = writeJSON(c, ack{Err: err.Error()})
		return
	}
	conn, err := newUDPSocket(0)
	if err != nil {
		_ = writeJSON(c, ack{Err: err.Error()})
		return
	}
	defer conn.Close()

	enc, cipherName, pub, box, err := negotiateCryptoServer(h, session)
	if err != nil {
		_ = writeJSON(c, ack{Err: err.Error()})
		return
	}
	if err := writeJSON(c, ack{OK: true, UDPPort: udpPortOf(conn), Session: session, Name: h.Name,
		Encrypt: enc, Cipher: cipherName, PubKey: pub}); err != nil {
		return
	}
	if enc {
		s.Log.Printf("encryption enabled (%s) for %q", cipherName, h.Name)
	}

	stats := NewStats()
	rs := make(chan struct{})
	go stats.Reporter(os.Stderr, "recv", p.ReportInterval, rs)
	defer close(rs)

	rcv := NewReceiver(RecvConfig{
		Conn: conn, File: f, FileSize: h.Size,
		BlockSize: h.BlockSize, TotalBlocks: numBlocks(h.Size, h.BlockSize),
		Session: session, ReadWorkers: p.ReadWorkers,
		Rate:               p.rateConfig(h.RateBps),
		Crypto:             box,
		FeedbackIntervalUs: p.FeedbackIntervalUs, NetTickIntervalUs: p.NetTickIntervalUs,
		Stats: stats, Log: s.Log,
	})
	s.Log.Printf("recv %q (%s, %d blocks) from %s", h.Name, humanBytes(uint64(h.Size)), numBlocks(h.Size, h.BlockSize), c.RemoteAddr())
	if err := rcv.Run(stop); err != nil {
		s.Log.Printf("recv error: %v", err)
		return
	}
	fmt.Fprintln(os.Stderr, stats.Summary("recv"))
	if got, err := fileCRC32C(f); err == nil {
		if got != h.CRC32C {
			s.Log.Printf("INTEGRITY FAILURE %q: crc got=%08x want=%08x", h.Name, got, h.CRC32C)
		} else {
			s.Log.Printf("integrity OK %q (crc32c=%08x)", h.Name, got)
		}
	}
}

// sendToClient: client pulls a file; server is the data sender.
func (s *Server) sendToClient(c net.Conn, h hello, session uint32, p TransferParams, stop <-chan struct{}) {
	inPath := filepath.Join(s.Dir, filepath.Base(h.Name))
	f, err := os.Open(inPath)
	if err != nil {
		_ = writeJSON(c, ack{Err: err.Error()})
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		_ = writeJSON(c, ack{Err: err.Error()})
		return
	}
	crc, err := fileCRC32C(f)
	if err != nil {
		_ = writeJSON(c, ack{Err: err.Error()})
		return
	}
	conn, err := newUDPSocket(0)
	if err != nil {
		_ = writeJSON(c, ack{Err: err.Error()})
		return
	}
	defer conn.Close()

	enc, cipherName, pub, box, err := negotiateCryptoServer(h, session)
	if err != nil {
		_ = writeJSON(c, ack{Err: err.Error()})
		return
	}
	if err := writeJSON(c, ack{
		OK: true, UDPPort: udpPortOf(conn), Session: session,
		Size: fi.Size(), CRC32C: crc, Name: h.Name,
		Encrypt: enc, Cipher: cipherName, PubKey: pub,
	}); err != nil {
		return
	}
	if enc {
		s.Log.Printf("encryption enabled (%s) for %q", cipherName, h.Name)
	}

	stats := NewStats()
	rs := make(chan struct{})
	go stats.Reporter(os.Stderr, "send", p.ReportInterval, rs)
	defer close(rs)

	snd := NewSender(SendConfig{
		Conn: conn, Peer: nil, File: f, FileSize: fi.Size(),
		BlockSize: h.BlockSize, TotalBlocks: numBlocks(fi.Size(), h.BlockSize),
		Session: session, Rate: p.rateConfig(h.RateBps),
		ReadWorkers: p.ReadWorkers, Crypto: box, Stats: stats, Log: s.Log,
	})
	s.Log.Printf("send %q (%s, %d blocks) to %s", h.Name, humanBytes(uint64(fi.Size())), numBlocks(fi.Size(), h.BlockSize), c.RemoteAddr())
	if err := snd.Run(stop); err != nil {
		s.Log.Printf("send error: %v", err)
		return
	}
	fmt.Fprintln(os.Stderr, stats.Summary("send"))
}
