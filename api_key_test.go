package apikey

import (
	"regexp"
	"strings"
	"testing"
)

func TestNewApiKeyGeneratorValidation(t *testing.T) {
	// Empty prefix
	_, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: ""})
	if err == nil {
		t.Error("expected error for empty prefix")
	}
	// Too long prefix
	_, err = NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "abcdefghijklmnopqrstuvwxyz1234567890"})
	if err == nil {
		t.Error("expected error for long prefix")
	}
	// Separator in prefix (default separator is '_')
	_, err = NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "bad_pre"})
	if err == nil {
		t.Error("expected error for prefix containing default separator '_'")
	}
	// Custom separator in prefix
	_, err = NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "bad#pre", TokenSeparator: '#'})
	if err == nil {
		t.Error("expected error for prefix containing custom separator '#'")
	}
	// Invalid char
	_, err = NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "bad!prefix"})
	if err == nil {
		t.Error("expected error for prefix with invalid char")
	}
	// Short token bytes below minimum (8)
	_, err = NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "valid", ShortTokenBytes: 7})
	if err == nil {
		t.Error("expected error for short token bytes < 8")
	}
	// Long token bytes below minimum (32)
	_, err = NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "valid", LongTokenBytes: 31})
	if err == nil {
		t.Error("expected error for long token bytes < 32")
	}
}

func TestGetTokenComponentsError(t *testing.T) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "foo"})
	// Bad part count
	_, err := gen.GetTokenComponents("a_b")
	if err == nil {
		t.Error("expected error for bad token format in GetTokenComponents")
	}
	// Prefix mismatch
	_, err = gen.GetTokenComponents("bar_shorttoken123_longtoken1234567890")
	if err == nil {
		t.Error("expected error for prefix mismatch in GetTokenComponents")
	}
	// Empty short token
	_, err = gen.GetTokenComponents("foo__longtoken1234567890")
	if err == nil {
		t.Error("expected error for empty short token in GetTokenComponents")
	}
	// Empty long token
	_, err = gen.GetTokenComponents("foo_shorttoken123_")
	if err == nil {
		t.Error("expected error for empty long token in GetTokenComponents")
	}
	// All empty components
	_, err = gen.GetTokenComponents("__")
	if err == nil {
		t.Error("expected error for empty components in GetTokenComponents")
	}
}

func TestCheckAPIKeyError(t *testing.T) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "foo"})
	_, err := gen.CheckAPIKey("a_b", "hash")
	if err == nil {
		t.Error("expected error for bad token format in CheckAPIKey")
	}
	// Prefix mismatch
	_, err = gen.CheckAPIKey("bar_shorttoken123_longtoken1234567890", "hash")
	if err == nil {
		t.Error("expected error for prefix mismatch in CheckAPIKey")
	}
}

type customGen struct{}

func (c *customGen) Generate(n int) (string, error) { return "SHORTTOKEN", nil }

type customHasher struct{}

func (c *customHasher) Hash(s string) (string, error) { return "HASHED" + s, nil }
func (c *customHasher) Verify(token, hash string) bool {
	h, _ := c.Hash(token)
	return h == hash
}

func TestNewApiKeyGeneratorWithFuncs(t *testing.T) {
	gen, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{
		TokenPrefix:      "pref",
		TokenIdGenerator: &customGen{},
		TokenHasher:      &customHasher{},
	})

	if err != nil {
		t.Fatalf("NewApiKeyGenerator failed: %v", err)
	}
	key, err := gen.GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}
	if key.ShortToken != "SHORTTOKEN" {
		t.Errorf("custom idGen not used for short token: got %q", key.ShortToken)
	}
	if key.LongToken == "SHORTTOKEN" {
		t.Errorf("long token should not use idGen")
	}
	expectedHash, _ := (&customHasher{}).Hash(key.LongToken)
	if key.LongTokenHash != expectedHash {
		t.Errorf("custom hasher not used: got %q", key.LongTokenHash)
	}
}

func TestGenerateAPIKey(t *testing.T) {
	prefix := "mycorp"
	gen, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: prefix})
	if err != nil {
		t.Fatalf("NewApiGenerator failed: %v", err)
	}
	key, err := gen.GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("key is nil")
	}
	if key.Prefix != prefix || key.ShortToken == "" || key.LongToken == "" || key.LongTokenHash == "" || key.Token == "" {
		t.Error("one or more fields are empty or invalid")
	}
	if got, want := key.Token[:len(prefix)], prefix; got != want {
		t.Errorf("prefix mismatch: got %q, want %q", got, want)
	}
	// Check format: prefix_short_long
	re := regexp.MustCompile(`^[a-zA-Z0-9]+_[A-Za-z0-9\-_]+_[A-Za-z0-9\-_]+$`)
	if !re.MatchString(key.Token) {
		t.Errorf("token format invalid: %q", key.Token)
	}
}

func TestGetTokenComponents(t *testing.T) {
	prefix := "abc"
	gen, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: prefix})
	if err != nil {
		t.Fatalf("NewApiGenerator failed: %v", err)
	}
	key, _ := gen.GenerateAPIKey()
	parsed, err := gen.GetTokenComponents(key.Token)
	if err != nil {
		t.Fatalf("GetTokenComponents failed: %v", err)
	}
	if parsed.Prefix != prefix {
		t.Errorf("Prefix mismatch: got %q, want %q", parsed.Prefix, prefix)
	}
	if parsed.ShortToken != key.ShortToken {
		t.Errorf("ShortToken mismatch: got %q, want %q", parsed.ShortToken, key.ShortToken)
	}
	if parsed.LongToken != key.LongToken {
		t.Errorf("LongToken mismatch: got %q, want %q", parsed.LongToken, key.LongToken)
	}
}

func TestCheckAPIKey(t *testing.T) {
	prefix := "foo"
	gen, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: prefix})
	if err != nil {
		t.Fatalf("NewApiGenerator failed: %v", err)
	}
	key, _ := gen.GenerateAPIKey()

	ok, err := gen.CheckAPIKey(key.Token, key.LongTokenHash)
	if err != nil {
		t.Fatalf("CheckAPIKey failed: %v", err)
	}
	if !ok {
		t.Error("CheckAPIKey returned false for valid key")
	}
	// Negative test
	ok, _ = gen.CheckAPIKey(key.Token, "beef")
	if ok {
		t.Error("CheckAPIKey returned true for invalid hash")
	}
}

func TestAPIKeyStringRedaction(t *testing.T) {
	key := &APIKey{
		Prefix:        "mycorp",
		ShortToken:    "abcdefgh1234",
		LongToken:     "supersecretlongtokenthatmustneverbelogged",
		LongTokenHash: "hashedsecret",
		Token:         "mycorp_abcdefgh1234_supersecretlongtokenthatmustneverbelogged",
	}

	str := key.String()
	if strings.Contains(str, key.LongToken) {
		t.Errorf("APIKey.String() exposed plaintext secret: %s", str)
	}
	if !strings.Contains(str, "[REDACTED]") {
		t.Errorf("APIKey.String() did not include redaction marker: %s", str)
	}
	if !strings.Contains(str, key.ShortToken) {
		t.Errorf("APIKey.String() missing short token identifier: %s", str)
	}
}
