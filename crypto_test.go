package girth

import (
	"bytes"
	"testing"
)

// pairBoxes derives a mirrored client/server AEAD pair for cipherName, exactly
// as the handshake would (each side: own private key + peer public key).
func pairBoxes(t *testing.T, cipherName string) (client, server *aeadBox) {
	t.Helper()
	cpriv, cpub, err := genKeypair()
	if err != nil {
		t.Fatal(err)
	}
	spriv, spub, err := genKeypair()
	if err != nil {
		t.Fatal(err)
	}
	const session = 0xABCD1234
	client, err = deriveAEAD(cpriv, spub, session, cipherName)
	if err != nil {
		t.Fatalf("client deriveAEAD: %v", err)
	}
	server, err = deriveAEAD(spriv, cpub, session, cipherName)
	if err != nil {
		t.Fatalf("server deriveAEAD: %v", err)
	}
	return client, server
}

func sealCopy(t *testing.T, b *aeadBox, plaintext []byte, seq uint64) []byte {
	t.Helper()
	buf := make([]byte, DataHeaderSize+len(plaintext)+aeadTagLen)
	copy(buf[DataHeaderSize:], plaintext)
	size := b.sealData(buf, DataHeaderSize, len(plaintext), seq)
	if size != DataHeaderSize+len(plaintext)+aeadTagLen {
		t.Fatalf("sealed size: got %d want %d", size, DataHeaderSize+len(plaintext)+aeadTagLen)
	}
	return buf[DataHeaderSize:size]
}

func TestAEADRoundTripBothSuites(t *testing.T) {
	for _, name := range []string{cipherAESGCM, cipherChaCha} {
		t.Run(name, func(t *testing.T) {
			client, server := pairBoxes(t, name)
			plaintext := []byte("the quick brown fox jumps over the lazy dog")

			// Seal on client, open on server: shared key must agree.
			payload := sealCopy(t, client, plaintext, 42)
			if bytes.Equal(payload[:len(plaintext)], plaintext) {
				t.Fatal("payload not encrypted (matches plaintext)")
			}
			pt, ok := server.openData(payload, len(plaintext), 42)
			if !ok {
				t.Fatal("open failed for valid packet")
			}
			if !bytes.Equal(pt, plaintext) {
				t.Fatalf("decrypted mismatch: got %q", pt)
			}
		})
	}
}

func TestAEADRejectsTampering(t *testing.T) {
	client, server := pairBoxes(t, cipherAESGCM)
	plaintext := []byte("sensitive bytes")

	// Flip a ciphertext byte.
	payload := sealCopy(t, client, plaintext, 7)
	payload[0] ^= 0xFF
	if _, ok := server.openData(payload, len(plaintext), 7); ok {
		t.Fatal("open accepted tampered ciphertext")
	}

	// Flip a tag byte.
	payload = sealCopy(t, client, plaintext, 7)
	payload[len(payload)-1] ^= 0xFF
	if _, ok := server.openData(payload, len(plaintext), 7); ok {
		t.Fatal("open accepted tampered tag")
	}

	// Wrong block sequence (nonce mismatch) must fail authentication.
	payload = sealCopy(t, client, plaintext, 7)
	if _, ok := server.openData(payload, len(plaintext), 8); ok {
		t.Fatal("open accepted wrong-seq nonce")
	}
}

func TestAEADWrongKeyFails(t *testing.T) {
	client, _ := pairBoxes(t, cipherChaCha)
	_, other := pairBoxes(t, cipherChaCha) // independent session key
	payload := sealCopy(t, client, []byte("payload"), 1)
	if _, ok := other.openData(payload, len("payload"), 1); ok {
		t.Fatal("open accepted packet sealed under a different key")
	}
}

func TestAEADEmptyPayload(t *testing.T) {
	client, server := pairBoxes(t, cipherAESGCM)
	payload := sealCopy(t, client, nil, 0)
	pt, ok := server.openData(payload, 0, 0)
	if !ok || len(pt) != 0 {
		t.Fatalf("empty payload roundtrip failed: ok=%v len=%d", ok, len(pt))
	}
}

func TestChooseCipher(t *testing.T) {
	cases := []struct {
		prefer, peer []string
		want         string
	}{
		{[]string{cipherAESGCM, cipherChaCha}, []string{cipherChaCha, cipherAESGCM}, cipherAESGCM},
		{[]string{cipherChaCha, cipherAESGCM}, []string{cipherAESGCM}, cipherAESGCM},
		{[]string{cipherAESGCM}, []string{cipherChaCha}, ""},
		{[]string{cipherChaCha, cipherAESGCM}, []string{cipherChaCha, cipherAESGCM}, cipherChaCha},
	}
	for i, c := range cases {
		if got := chooseCipher(c.prefer, c.peer); got != c.want {
			t.Fatalf("case %d: chooseCipher=%q want %q", i, got, c.want)
		}
	}
}

func TestServerNegotiationNoEncrypt(t *testing.T) {
	enc, _, _, box, err := negotiateCryptoServer(hello{Encrypt: false}, 1)
	if err != nil || enc || box != nil {
		t.Fatalf("no-encrypt negotiation: enc=%v box=%v err=%v", enc, box, err)
	}
}

func TestClientCryptoFailsClosed(t *testing.T) {
	// User wanted encryption but server declined -> must error, not downgrade.
	if _, err := clientCrypto(true, ack{Encrypt: false}, nil); err == nil {
		t.Fatal("clientCrypto should fail closed when server declines")
	}
}
