// Package apikey provides functions to generate and parse Seam-style API keys with base64 encoding.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

type ApiKeyGeneratorOptions struct {
	Prefix            string
	RandomIdGenerator RandomIdGenerator
	TokenHasher       TokenHasher
}

type APIKeyGenerator struct {
	prefix      string
	randomIds   RandomIdGenerator
	tokenHasher TokenHasher
}

const (
	shortTokenBytes = 8
	longTokenBytes  = 32
	tokenSeparator  = "#"
)

// APIKey holds the components of a generated API key.
type APIKey struct {
	ShortToken    string
	LongToken     string
	LongTokenHash string
	Token         string
}

// RandomIdGenerator defines an interface for generating random IDs as a string.
type RandomIdGenerator interface {
	Generate(n int) (string, error)
}

// TokenHasher defines an interface for hashing a token string.
type TokenHasher interface {
	Hash(token string) string
}

// NewApiKeyGenerator creates a new APIKeyGenerator with default idGenerator and tokenHasher.

// NewApiKeyGenerator creates a new APIKeyGenerator using options. Id generator and hasher are optional.
func NewApiKeyGenerator(opts ApiKeyGeneratorOptions) (*APIKeyGenerator, error) {
	if len(opts.Prefix) == 0 || len(opts.Prefix) > 32 {
		return nil, fmt.Errorf("prefix must be 1-32 characters long")
	}
	for _, c := range opts.Prefix {
		if !(('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') || c == '-' || c == '_') {
			return nil, fmt.Errorf("prefix contains invalid character: %q", c)
		}
		if string(c) == tokenSeparator {
			return nil, fmt.Errorf("prefix cannot contain '%s' character", tokenSeparator)
		}
	}
	idGen := opts.RandomIdGenerator
	if idGen == nil {
		idGen = &DefaultRandomIdGenerator{}
	}
	hasher := opts.TokenHasher
	if hasher == nil {
		hasher = &Sha256Hasher{}
	}
	return &APIKeyGenerator{
		prefix:      opts.Prefix,
		randomIds:   idGen,
		tokenHasher: hasher,
	}, nil
}

// DefaultRandomIdGenerator implements RandomIdGenerator using crypto/rand and base64.
type DefaultRandomIdGenerator struct{}

func (d *DefaultRandomIdGenerator) Generate(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Sha256Hasher implements TokenHasher using SHA256.
type Sha256Hasher struct{}

func (d *Sha256Hasher) Hash(longToken string) string {
	h := sha256.Sum256([]byte(longToken))
	return fmt.Sprintf("%x", h[:])
}

// GenerateAPIKey generates a new API key using the generator's prefix.
func (a *APIKeyGenerator) GenerateAPIKey() (*APIKey, error) {
	shortToken, err := a.randomIds.Generate(shortTokenBytes)
	if err != nil {
		return nil, err
	}
	longToken, err := a.randomBase64(longTokenBytes)
	if err != nil {
		return nil, err
	}
	token := fmt.Sprintf("%s%s%s%s%s", a.prefix, tokenSeparator, shortToken, tokenSeparator, longToken)
	hash := a.tokenHasher.Hash(longToken)
	return &APIKey{
		ShortToken:    shortToken,
		LongToken:     longToken,
		LongTokenHash: hash,
		Token:         token,
	}, nil
}

// randomBase64 returns a URL-safe base64 string of n random bytes, without padding.
func (a *APIKeyGenerator) randomBase64(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ExtractShortToken extracts the short token from a full API key string.
func (a *APIKeyGenerator) ExtractShortToken(token string) (string, error) {
	parts := strings.Split(token, tokenSeparator)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}
	return parts[1], nil
}

// ExtractLongToken extracts the long token from a full API key string.
func (a *APIKeyGenerator) ExtractLongToken(token string) (string, error) {
	parts := strings.Split(token, tokenSeparator)
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}
	return parts[2], nil
}

// GetTokenComponents parses a full API key string into its components.
func (a *APIKeyGenerator) GetTokenComponents(token string) (*APIKey, error) {
	parts := strings.Split(token, tokenSeparator)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}
	hash := a.tokenHasher.Hash(parts[2])
	return &APIKey{
		ShortToken:    parts[1],
		LongToken:     parts[2],
		LongTokenHash: hash,
		Token:         token,
	}, nil
}

// CheckAPIKey verifies that the hash of the long token in the key matches the provided hash.
func (a *APIKeyGenerator) CheckAPIKey(token, hash string) (bool, error) {
	longToken, err := a.ExtractLongToken(token)
	if err != nil {
		return false, err
	}
	return a.tokenHasher.Hash(longToken) == hash, nil
}
