package apikey

import (
	"bytes"
	"strings"
	"testing"
)

func TestZeroizeBytes(t *testing.T) {
	b := []byte("confidential-secret-key-data-1234567890")
	ZeroizeBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("byte at index %d was not zeroed: %d", i, v)
		}
	}

	// Nil / empty check
	ZeroizeBytes(nil)
	ZeroizeBytes([]byte{})
}

func TestZeroizeString(t *testing.T) {
	// Dynamically allocated string slice
	raw := []byte("confidential-string-data-1234567890")
	s := string(raw)

	ZeroizeString(&s)
	if s != "" {
		t.Errorf("expected string to be reset to empty, got %q", s)
	}

	// Verify backing bytes in raw are wiped if shared or non-panicking
	ZeroizeString(nil)
	empty := ""
	ZeroizeString(&empty)
}

func TestAPIKey_Zeroize(t *testing.T) {
	gen, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "zero"})
	if err != nil {
		t.Fatalf("NewApiKeyGenerator failed: %v", err)
	}
	key, err := gen.GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}

	if key.LongToken == "" || key.Token == "" {
		t.Fatal("generated key fields should not be empty")
	}

	key.Zeroize()

	if key.LongToken != "" {
		t.Errorf("expected LongToken to be empty after Zeroize, got %q", key.LongToken)
	}
	if key.Token != "" {
		t.Errorf("expected Token to be empty after Zeroize, got %q", key.Token)
	}
	if key.Prefix != "" || key.ShortToken != "" || key.LongTokenHash != "" {
		t.Errorf("expected all metadata to be cleared after Zeroize")
	}

	// Nil receiver safe
	var nilKey *APIKey
	nilKey.Zeroize()
}

func TestAPIKeyBytes_GenerateAndZeroize(t *testing.T) {
	gen, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "bytes"})
	if err != nil {
		t.Fatalf("NewApiKeyGenerator failed: %v", err)
	}

	keyBytes, err := gen.GenerateAPIKeyBytes()
	if err != nil {
		t.Fatalf("GenerateAPIKeyBytes failed: %v", err)
	}

	if len(keyBytes.LongToken) == 0 || len(keyBytes.Token) == 0 {
		t.Fatal("keyBytes fields should not be empty")
	}

	// Check stringer redaction
	str := keyBytes.String()
	if strings.Contains(str, string(keyBytes.LongToken)) {
		t.Errorf("APIKeyBytes.String() exposed secret: %s", str)
	}
	if !strings.Contains(str, "[REDACTED]") {
		t.Errorf("APIKeyBytes.String() missing [REDACTED]")
	}

	// Validate components
	parsed, err := gen.GetTokenComponentsBytes(keyBytes.Token)
	if err != nil {
		t.Fatalf("GetTokenComponentsBytes failed: %v", err)
	}
	if !bytes.Equal(parsed.ShortToken, keyBytes.ShortToken) {
		t.Errorf("ShortToken mismatch: got %s, want %s", parsed.ShortToken, keyBytes.ShortToken)
	}

	// CheckAPIKeyBytes
	ok, err := gen.CheckAPIKeyBytes(keyBytes.Token, keyBytes.LongTokenHash)
	if err != nil {
		t.Fatalf("CheckAPIKeyBytes failed: %v", err)
	}
	if !ok {
		t.Errorf("CheckAPIKeyBytes returned false for valid key")
	}

	// Zeroize
	keyBytes.Zeroize()
	for i, b := range keyBytes.LongToken {
		if b != 0 {
			t.Errorf("LongToken byte at %d was not zeroed: %d", i, b)
		}
	}
	for i, b := range keyBytes.Token {
		if b != 0 {
			t.Errorf("Token byte at %d was not zeroed: %d", i, b)
		}
	}

	// Nil receiver safe
	var nilKeyBytes *APIKeyBytes
	nilKeyBytes.Zeroize()
}
