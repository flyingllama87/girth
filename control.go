package girth

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

// The control plane runs over TCP. It negotiates the session, exchanges file
// metadata and an integrity checksum, and tells each side where to send UDP
// traffic. After the handshake, the data plane (UDP) takes over.

// Direction of the bulk transfer relative to the client.
const (
	ModeSend = "send" // client pushes a file to the server
	ModeRecv = "recv" // client pulls a file from the server
)

// hello is the client's opening control message.
type hello struct {
	Version   int    `json:"version"`
	Mode      string `json:"mode"` // ModeSend / ModeRecv
	Name      string `json:"name"` // file name (basename used on the wire)
	Size      int64  `json:"size"` // file size (send mode)
	BlockSize int    `json:"blockSize"`
	RateBps   uint64 `json:"rateBps"` // target/initial injection rate
	MaxBps    uint64 `json:"maxBps"`  // ceiling for adaptive rate
	Adaptive  bool   `json:"adaptive"`
	AlphaBps  uint64 `json:"alphaBps"`
	CRC32C    uint32 `json:"crc32c"` // whole-file CRC32C (send mode)

	// Data-plane encryption negotiation (optional).
	Encrypt bool     `json:"encrypt,omitempty"` // client requests encryption
	Ciphers []string `json:"ciphers,omitempty"` // supported AEAD suites, preferred first
	PubKey  []byte   `json:"pubKey,omitempty"`  // client ephemeral X25519 public key
}

// ack is the server's reply.
type ack struct {
	OK      bool   `json:"ok"`
	Err     string `json:"err,omitempty"`
	UDPPort int    `json:"udpPort"` // server's UDP port
	Session uint32 `json:"session"`
	Size    int64  `json:"size"`   // file size (recv mode: server tells client)
	CRC32C  uint32 `json:"crc32c"` // whole-file CRC32C (recv mode)
	Name    string `json:"name"`

	// Data-plane encryption result (echoed when Encrypt was requested).
	Encrypt bool   `json:"encrypt,omitempty"` // server enabled encryption
	Cipher  string `json:"cipher,omitempty"`  // chosen AEAD suite
	PubKey  []byte `json:"pubKey,omitempty"`  // server ephemeral X25519 public key
}

func writeJSON(c net.Conn, v any) error {
	c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	defer c.SetWriteDeadline(time.Time{})
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var lenbuf [4]byte
	putU32(lenbuf[:], uint32(len(b)))
	if _, err := c.Write(lenbuf[:]); err != nil {
		return err
	}
	_, err = c.Write(b)
	return err
}

func readJSON(c net.Conn, v any) error {
	c.SetReadDeadline(time.Now().Add(120 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	var lenbuf [4]byte
	if _, err := io.ReadFull(c, lenbuf[:]); err != nil {
		return err
	}
	n := getU32(lenbuf[:])
	if n > 1<<20 {
		return fmt.Errorf("control message too large: %d", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// TransferParams collects the user-tunable knobs shared by client and server.
type TransferParams struct {
	BlockSize          int
	RateBps            uint64
	MaxBps             uint64
	Adaptive           bool
	AlphaBps           uint64
	ReadWorkers        int
	FeedbackIntervalUs int
	NetTickIntervalUs  int
	ReportInterval     time.Duration
	Verbose            bool
	Encrypt            bool // client: request data-plane encryption
}

// DefaultParams returns sensible defaults.
func DefaultParams() TransferParams {
	return TransferParams{
		BlockSize:          DefaultBlockSize,
		RateBps:            100_000_000, // 100 Mbps
		MaxBps:             10_000_000_000,
		Adaptive:           false,
		AlphaBps:           30_000_000,
		ReadWorkers:        0, // 0 => auto
		FeedbackIntervalUs: 5000,
		NetTickIntervalUs:  10000,
		ReportInterval:     time.Second,
		Verbose:            false,
	}
}

func (p TransferParams) rateConfig(target uint64) RateConfig {
	mode := RateFixed
	if p.Adaptive {
		mode = RateAdaptive
	}
	return RateConfig{
		Mode:      mode,
		TargetBps: target,
		MaxBps:    p.MaxBps,
		Alpha:     float64(p.AlphaBps),
	}
}

func putU32(b []byte, v uint32) {
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}
func getU32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// fileCRC32C computes the whole-file CRC32C for end-to-end integrity checks.
func fileCRC32C(f *os.File) (uint32, error) {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	h := crc32.New(crcTable)
	buf := make([]byte, 1<<20)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	return h.Sum32(), nil
}

func basename(p string) string { return filepath.Base(p) }

// negotiateCryptoServer completes the server side of the key exchange for a
// hello requesting encryption. It returns the fields to echo in the ack plus
// the derived AEAD. If the client did not request encryption it returns a
// disabled result with a nil box.
func negotiateCryptoServer(h hello, session uint32) (enc bool, cipherName string, pub []byte, box *aeadBox, err error) {
	if !h.Encrypt {
		return false, "", nil, nil, nil
	}
	cipherName = chooseCipher(localCiphers(), h.Ciphers)
	if cipherName == "" {
		return false, "", nil, nil, fmt.Errorf("no common cipher suite")
	}
	priv, pub, err := genKeypair()
	if err != nil {
		return false, "", nil, nil, err
	}
	box, err = deriveAEAD(priv, h.PubKey, session, cipherName)
	if err != nil {
		return false, "", nil, nil, err
	}
	return true, cipherName, pub, box, nil
}
