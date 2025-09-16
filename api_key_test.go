package apikey

import (
	"fmt"
	"regexp"
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
	// Invalid char
	_, err = NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "bad#prefix"})
	if err == nil {
		t.Error("expected error for prefix with '#' char")
	}
	_, err = NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "bad!prefix"})
	if err == nil {
		t.Error("expected error for prefix with invalid char")
	}
}

func TestGetTokenComponentsError(t *testing.T) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "foo"})
	_, err := gen.GetTokenComponents("a#b")
	if err == nil {
		t.Error("expected error for bad token format in GetTokenComponents")
	}
}

func TestCheckAPIKeyError(t *testing.T) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "foo"})
	_, err := gen.CheckAPIKey("a#b", "hash")
	if err == nil {
		t.Error("expected error for bad token format in CheckAPIKey")
	}
}

type customGen struct{}

func (c *customGen) Generate(n int) (string, error) { return "SHORT", nil }

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
	if key.ShortToken != "SHORT" {
		t.Errorf("custom idGen not used for short token: got %q", key.ShortToken)
	}
	if key.LongToken == "SHORT" {
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
	if key.ShortToken == "" || key.LongToken == "" || key.LongTokenHash == "" || key.Token == "" {
		t.Error("one or more fields are empty")
	}
	if got, want := key.Token[:len(prefix)], prefix; got != want {
		t.Errorf("prefix mismatch: got %q, want %q", got, want)
	}
	// Check format: prefix#short#long
	re := regexp.MustCompile(`^[a-zA-Z0-9]+#[A-Za-z0-9\-_]+#[A-Za-z0-9\-_]+$`)
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
	fmt.Println("Generated token:", key.Token)
	fmt.Println("LongTokenHash:", key.LongTokenHash)
	parsed, err := gen.GetTokenComponents(key.Token)
	if err != nil {
		t.Fatalf("GetTokenComponents failed: %v", err)
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
