package apikey

import (
	"encoding/hex"
	"testing"
)

func TestSha256Hasher_HashAndVerify(t *testing.T) {
	hasher := &Sha256Hasher{}
	input := "testinput"
	hash, err := hasher.Hash(input)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if len(hash) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash))
	}
	_, err = hex.DecodeString(hash)
	if err != nil {
		t.Errorf("hash is not valid hex: %v", err)
	}
	// Deterministic
	hash2, err := hasher.Hash(input)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if hash != hash2 {
		t.Errorf("hash not deterministic: %q vs %q", hash, hash2)
	}
	// Verify
	if !hasher.Verify(input, hash) {
		t.Errorf("Verify failed for correct input and hash")
	}
	if hasher.Verify("wronginput", hash) {
		t.Errorf("Verify should fail for wrong input")
	}
}

type dummyHasher struct{}

func (d *dummyHasher) Hash(token string) (string, error) {
	return "dummy-" + token, nil
}

func (d *dummyHasher) Verify(token, hash string) bool {
	h, _ := d.Hash(token)
	return h == hash
}

func TestHasherInterface(t *testing.T) {
	var h Hasher = &dummyHasher{}
	out, err := h.Hash("abc")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if out != "dummy-abc" {
		t.Errorf("Hasher interface not working, got %q", out)
	}
	if !h.Verify("abc", "dummy-abc") {
		t.Errorf("Verify should succeed for dummy hasher")
	}
	if h.Verify("def", "dummy-abc") {
		t.Errorf("Verify should fail for dummy hasher with wrong input")
	}
}
