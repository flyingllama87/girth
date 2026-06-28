package girth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/sys/cpu"
)

// Optional confidentiality + integrity for the data plane.
//
// Key agreement runs over the (cleartext) TCP control channel: each side sends
// an ephemeral X25519 public key in the handshake, both compute the shared ECDH
// secret, and an HKDF-SHA256 derives the symmetric data key. Ephemeral keys give
// forward secrecy — the key exists only for the session and is never written
// down. (Only the file *data* is encrypted; the control metadata stays
// cleartext, see README.)
//
// Each DATA payload is sealed with an AEAD (AES-256-GCM where the CPU has AES
// instructions, else ChaCha20-Poly1305). The nonce is derived from the block
// sequence number, which is globally unique within a session and already in the
// (cleartext) header — so the decryptor reconstructs the nonce without it being
// transmitted, and a retransmit re-seals the same block to the same ciphertext
// (safe: identical plaintext under an identical nonce). The per-session key
// (keyed by the session id via HKDF salt) plus the per-block nonce bind both the
// session and the block index cryptographically; a forged or corrupted packet
// fails authentication and is dropped as "corrupt". The 16-byte tag replaces the
// per-packet CRC in encrypted mode (the whole-file CRC32C is still verified end
// to end).

// Cipher suite identifiers exchanged in the handshake.
const (
	cipherAESGCM = "aes-256-gcm"
	cipherChaCha = "chacha20-poly1305"

	aeadKeyLen   = 32 // 256-bit key for both suites
	aeadNonceLen = 12 // 96-bit nonce for both suites
	aeadTagLen   = 16 // 128-bit tag for both suites
)

// aesHardware reports whether the CPU has native AES instructions (AES-NI on
// x86, the ARMv8 Cryptographic Extension on arm64). When present, AES-GCM is the
// faster choice; otherwise ChaCha20-Poly1305 is preferred (fast and
// constant-time in pure SIMD software).
func aesHardware() bool { return cpu.X86.HasAES || cpu.ARM64.HasAES }

// localCiphers returns this host's supported suites in preference order.
func localCiphers() []string {
	if aesHardware() {
		return []string{cipherAESGCM, cipherChaCha}
	}
	return []string{cipherChaCha, cipherAESGCM}
}

// chooseCipher picks the first suite in our preference order that the peer also
// supports. Returns "" if there is no common suite.
func chooseCipher(prefer, peer []string) string {
	have := make(map[string]bool, len(peer))
	for _, c := range peer {
		have[c] = true
	}
	for _, c := range prefer {
		if have[c] {
			return c
		}
	}
	return ""
}

// aeadBox wraps a negotiated AEAD for the data plane. The underlying cipher.AEAD
// is safe for concurrent Seal/Open, so parallel ingest goroutines can decrypt
// simultaneously and prefetch/retransmit can encrypt concurrently.
type aeadBox struct {
	aead cipher.AEAD
	name string
}

func newAEAD(name string, key []byte) (*aeadBox, error) {
	if len(key) != aeadKeyLen {
		return nil, fmt.Errorf("girth: bad key length %d", len(key))
	}
	var a cipher.AEAD
	var err error
	switch name {
	case cipherAESGCM:
		var blk cipher.Block
		if blk, err = aes.NewCipher(key); err == nil {
			a, err = cipher.NewGCM(blk)
		}
	case cipherChaCha:
		a, err = chacha20poly1305.New(key)
	default:
		return nil, fmt.Errorf("girth: unknown cipher %q", name)
	}
	if err != nil {
		return nil, err
	}
	if a.NonceSize() != aeadNonceLen || a.Overhead() != aeadTagLen {
		return nil, fmt.Errorf("girth: cipher %q has unexpected geometry", name)
	}
	return &aeadBox{aead: a, name: name}, nil
}

func (b *aeadBox) overhead() int { return aeadTagLen }

// blockNonce derives the per-block nonce from the block sequence number.
func blockNonce(seq uint64) [aeadNonceLen]byte {
	var n [aeadNonceLen]byte
	// bytes [0:4] are a domain/zero prefix; the unique part is the 64-bit seq.
	binary.LittleEndian.PutUint64(n[4:], seq)
	return n
}

// sealData encrypts plen plaintext bytes located at buf[hdrLen:hdrLen+plen] in
// place, appending the tag, and returns the total PDU length (hdrLen + plen +
// tag). buf must have capacity for the tag. The header (buf[:hdrLen]) is left
// untouched so the cleartext routing fields remain readable.
func (b *aeadBox) sealData(buf []byte, hdrLen, plen int, seq uint64) int {
	nonce := blockNonce(seq)
	pt := buf[hdrLen : hdrLen+plen]
	ct := b.aead.Seal(buf[hdrLen:hdrLen], nonce[:], pt, nil)
	return hdrLen + len(ct)
}

// openData decrypts a DATA payload in place. payload is the bytes after the
// header (ciphertext followed by tag); plen is the plaintext length from the
// header. It returns the plaintext slice (aliasing payload) on success.
func (b *aeadBox) openData(payload []byte, plen int, seq uint64) ([]byte, bool) {
	if plen < 0 {
		return nil, false
	}
	ctLen := plen + aeadTagLen
	if ctLen > len(payload) {
		return nil, false
	}
	nonce := blockNonce(seq)
	ct := payload[:ctLen]
	pt, err := b.aead.Open(ct[:0], nonce[:], ct, nil)
	if err != nil {
		return nil, false
	}
	return pt, true
}

// ciphersIf returns the local cipher list when enc is set, else nil (so the
// handshake JSON omits it).
func ciphersIf(enc bool) []string {
	if enc {
		return localCiphers()
	}
	return nil
}

// clientCrypto completes the client side of the key exchange from the server's
// ack. It fails closed: if the user asked for encryption but the server did not
// enable it, that is an error rather than a silent downgrade to cleartext.
func clientCrypto(want bool, a ack, priv *ecdh.PrivateKey) (*aeadBox, error) {
	if !a.Encrypt {
		if want {
			return nil, fmt.Errorf("server declined encryption")
		}
		return nil, nil
	}
	if !want || priv == nil {
		return nil, fmt.Errorf("server enabled encryption unexpectedly")
	}
	return deriveAEAD(priv, a.PubKey, a.Session, a.Cipher)
}

// genKeypair creates an ephemeral X25519 keypair; pub is the 32-byte public key
// to put on the wire.
func genKeypair() (priv *ecdh.PrivateKey, pub []byte, err error) {
	priv, err = ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// deriveAEAD completes the handshake: it computes the X25519 shared secret with
// the peer's public key and derives the session AEAD via HKDF-SHA256, salted
// with the session id and bound to the negotiated cipher name. Both ends run
// this with mirrored keys and arrive at the same symmetric key.
func deriveAEAD(priv *ecdh.PrivateKey, peerPub []byte, session uint32, cipherName string) (*aeadBox, error) {
	rp, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("girth: bad peer public key: %w", err)
	}
	secret, err := priv.ECDH(rp)
	if err != nil {
		return nil, fmt.Errorf("girth: ECDH failed: %w", err)
	}
	var salt [4]byte
	binary.LittleEndian.PutUint32(salt[:], session)
	key, err := hkdf.Key(sha256.New, secret, salt[:], "girth data key "+cipherName, aeadKeyLen)
	if err != nil {
		return nil, fmt.Errorf("girth: HKDF failed: %w", err)
	}
	return newAEAD(cipherName, key)
}
