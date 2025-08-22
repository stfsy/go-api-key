package apikey

import (
	"encoding/hex"
	"testing"
)

func TestSha256Hasher_Hash(t *testing.T) {
	hasher := &Sha256Hasher{}
	input := "testinput"
	hash := hasher.Hash(input)
	if len(hash) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash))
	}
	_, err := hex.DecodeString(hash)
	if err != nil {
		t.Errorf("hash is not valid hex: %v", err)
	}
	// Deterministic
	hash2 := hasher.Hash(input)
	if hash != hash2 {
		t.Errorf("hash not deterministic: %q vs %q", hash, hash2)
	}
}

type dummyHasher struct{}

func (d *dummyHasher) Hash(token string) string {
	return "dummy-" + token
}

func TestHasherInterface(t *testing.T) {
	var h Hasher = &dummyHasher{}
	out := h.Hash("abc")
	if out != "dummy-abc" {
		t.Errorf("Hasher interface not working, got %q", out)
	}
}
