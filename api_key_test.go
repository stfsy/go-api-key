package apikey

import (
	"regexp"
	"testing"
)

func TestNewApiKeyGeneratorValidation(t *testing.T) {
	// Empty prefix
	_, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{Prefix: ""})
	if err == nil {
		t.Error("expected error for empty prefix")
	}
	// Too long prefix
	_, err = NewApiKeyGenerator(ApiKeyGeneratorOptions{Prefix: "abcdefghijklmnopqrstuvwxyz1234567890"})
	if err == nil {
		t.Error("expected error for long prefix")
	}
	// Invalid char
	_, err = NewApiKeyGenerator(ApiKeyGeneratorOptions{Prefix: "bad#prefix"})
	if err == nil {
		t.Error("expected error for prefix with '#' char")
	}
	_, err = NewApiKeyGenerator(ApiKeyGeneratorOptions{Prefix: "bad!prefix"})
	if err == nil {
		t.Error("expected error for prefix with invalid char")
	}
}

func TestExtractShortAndLongTokenErrors(t *testing.T) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{Prefix: "foo"})
	// Not enough parts
	_, err := gen.ExtractShortToken("a#b")
	if err == nil {
		t.Error("expected error for bad token format (short)")
	}
	_, err = gen.ExtractLongToken("a#b")
	if err == nil {
		t.Error("expected error for bad token format (long)")
	}
}

func TestGetTokenComponentsError(t *testing.T) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{Prefix: "foo"})
	_, err := gen.GetTokenComponents("a#b")
	if err == nil {
		t.Error("expected error for bad token format in GetTokenComponents")
	}
}

func TestCheckAPIKeyError(t *testing.T) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{Prefix: "foo"})
	_, err := gen.CheckAPIKey("a#b", "hash")
	if err == nil {
		t.Error("expected error for bad token format in CheckAPIKey")
	}
}

type customGen struct{}

func (c *customGen) Generate(n int) (string, error) { return "SHORT", nil }

type customHasher struct{}

func (c *customHasher) Hash(s string) string { return "HASHED" + s }

func TestNewApiKeyGeneratorWithFuncs(t *testing.T) {
	gen, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{
		Prefix:            "pref",
		RandomIdGenerator: &customGen{},
		TokenHasher:       &customHasher{},
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
	if key.LongTokenHash != "HASHED"+key.LongToken {
		t.Errorf("custom hasher not used: got %q", key.LongTokenHash)
	}
}

func TestGenerateAPIKey(t *testing.T) {
	prefix := "mycorp"
	gen, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{Prefix: prefix})
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

func TestExtractShortAndLongToken(t *testing.T) {
	prefix := "test"
	gen, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{Prefix: prefix})
	if err != nil {
		t.Fatalf("NewApiGenerator failed: %v", err)
	}
	key, _ := gen.GenerateAPIKey()
	short, err := gen.ExtractShortToken(key.Token)
	if err != nil {
		t.Fatalf("ExtractShortToken failed: %v", err)
	}
	if short != key.ShortToken {
		t.Errorf("short token mismatch: got %q, want %q", short, key.ShortToken)
	}
	long, err := gen.ExtractLongToken(key.Token)
	if err != nil {
		t.Fatalf("ExtractLongToken failed: %v", err)
	}
	if long != key.LongToken {
		t.Errorf("long token mismatch: got %q, want %q", long, key.LongToken)
	}
}

func TestGetTokenComponents(t *testing.T) {
	prefix := "abc"
	gen, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{Prefix: prefix})
	if err != nil {
		t.Fatalf("NewApiGenerator failed: %v", err)
	}
	key, _ := gen.GenerateAPIKey()
	parsed, err := gen.GetTokenComponents(key.Token)
	if err != nil {
		t.Fatalf("GetTokenComponents failed: %v", err)
	}
	if parsed.ShortToken != key.ShortToken || parsed.LongToken != key.LongToken || parsed.LongTokenHash != key.LongTokenHash {
		t.Error("parsed components do not match original")
	}
}

func TestCheckAPIKey(t *testing.T) {
	prefix := "foo"
	gen, err := NewApiKeyGenerator(ApiKeyGeneratorOptions{Prefix: prefix})
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
