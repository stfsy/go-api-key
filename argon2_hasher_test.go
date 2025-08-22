package apikey

import (
	"strings"
	"testing"
	"time"
)

func TestArgon2IdHasher_HashAndVerify(t *testing.T) {
	hasher := &Argon2IdHasher{}
	input := "testinput"
	hash, err := hasher.Hash(input)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if hash == "" {
		t.Error("expected non-empty hash")
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash does not have argon2id prefix: %q", hash)
	}
	// Hash should be different for different inputs
	hash2, err := hasher.Hash("differentinput")
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if hash == hash2 {
		t.Error("hash should differ for different inputs")
	}
	// Hash should be different for same input (due to random salt)
	hash3, err := hasher.Hash(input)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	if hash == hash3 {
		t.Error("hash should differ for same input due to salt")
	}
	// Verify
	if !hasher.Verify(input, hash) {
		t.Errorf("Verify failed for correct input and hash")
	}
	if hasher.Verify("wronginput", hash) {
		t.Errorf("Verify should fail for wrong input")
	}
}

func TestArgon2IdHasher_Hash_Performance(t *testing.T) {
	hasher := &Argon2IdHasher{}
	input := "performance-test-input"
	start := time.Now()
	_, err := hasher.Hash(input)
	if err != nil {
		t.Fatalf("Hash returned error: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < 100*time.Millisecond {
		t.Errorf("Argon2IdHasher.Hash was too fast: %v (want >= 100ms)", elapsed)
	}
}
