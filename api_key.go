// Package apikey provides functions to generate and parse Seam-style API keys with base64 encoding.
package apikey

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	defaultShortTokenBytes = 8
	defaultLongTokenBytes  = 64
	defaultTokenSeparator  = '#'
)

type ApiKeyGeneratorOptions struct {
	TokenPrefix         string
	TokenSeparator      rune // now a rune, not a string
	TokenIdGenerator    RandomBytesGenerator
	TokenBytesGenerator RandomBytesGenerator
	TokenHasher         Hasher
	ShortTokenBytes     int
	LongTokenBytes      int
}

type APIKeyGenerator struct {
	tokenPrefix         string
	tokenSeparator      rune
	tokenIdGenerator    RandomBytesGenerator
	tokenBytesGenerator RandomBytesGenerator
	tokenHasher         Hasher
	shortTokenBytes     int
	longTokenBytes      int
}

// APIKey holds the components of a generated API key.
type APIKey struct {
	ShortToken    string
	LongToken     string
	LongTokenHash string
	Token         string
}

// NewApiKeyGenerator creates a new APIKeyGenerator using options. Id generator and hasher are optional.
func NewApiKeyGenerator(opts ApiKeyGeneratorOptions) (*APIKeyGenerator, error) {
	if len(opts.TokenPrefix) == 0 {
		return nil, fmt.Errorf("token prefix must be not be empty")
	}
	// Regex: only a-zA-Z0-9_- and must not contain the separator
	validPrefix := `^[a-zA-Z0-9_-]{1,8}$`
	matched, err := regexp.MatchString(validPrefix, opts.TokenPrefix)
	if err != nil {
		return nil, fmt.Errorf("token prefix validation failed: %v", err)
	}
	if !matched {
		return nil, fmt.Errorf("token prefix must match %s", validPrefix)
	}
	tokenBytesGenerator := opts.TokenBytesGenerator
	if tokenBytesGenerator == nil {
		tokenBytesGenerator = &DefaultRandomBytesGenerator{}
	}
	tokenIdGenerator := opts.TokenIdGenerator
	if tokenIdGenerator == nil {
		tokenIdGenerator = &DefaultRandomBytesGenerator{}
	}
	hasher := opts.TokenHasher
	if hasher == nil {
		hasher = &Argon2IdHasher{}
	}
	shortTokenBytes := opts.ShortTokenBytes
	if shortTokenBytes == 0 {
		shortTokenBytes = defaultShortTokenBytes
	}
	longTokenBytes := opts.LongTokenBytes
	if longTokenBytes == 0 {
		longTokenBytes = defaultLongTokenBytes
	}
	tokenSeparator := opts.TokenSeparator
	if tokenSeparator == 0 {
		tokenSeparator = defaultTokenSeparator
	}
	return &APIKeyGenerator{
		tokenPrefix:         opts.TokenPrefix,
		tokenBytesGenerator: tokenBytesGenerator,
		tokenIdGenerator:    tokenIdGenerator,
		tokenHasher:         hasher,
		tokenSeparator:      tokenSeparator,
		shortTokenBytes:     shortTokenBytes,
		longTokenBytes:      longTokenBytes,
	}, nil
}

// GenerateAPIKey generates a new API key using the generator's prefix.
func (a *APIKeyGenerator) GenerateAPIKey() (*APIKey, error) {
	shortToken, err := a.tokenIdGenerator.Generate(a.shortTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate short token: %v", err)
	}
	longToken, err := a.tokenBytesGenerator.Generate(a.longTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate long token: %v", err)
	}
	sep := string(a.tokenSeparator)
	token := fmt.Sprintf("%s%s%s%s%s", a.tokenPrefix, sep, shortToken, sep, longToken)
	hash, err := a.tokenHasher.Hash(longToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash long token: %v", err)
	}
	return &APIKey{
		ShortToken:    shortToken,
		LongToken:     longToken,
		LongTokenHash: hash,
		Token:         token,
	}, nil
}

// ExtractShortToken extracts the short token from a full API key string.
func (a *APIKeyGenerator) ExtractShortToken(token string) (string, error) {
	parts := strings.Split(token, string(a.tokenSeparator))
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}
	return parts[1], nil
}

// ExtractLongToken extracts the long token from a full API key string.
func (a *APIKeyGenerator) ExtractLongToken(token string) (string, error) {
	parts := strings.Split(token, string(a.tokenSeparator))
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid token format")
	}
	return parts[2], nil
}

// GetTokenComponents parses a full API key string into its components.
func (a *APIKeyGenerator) GetTokenComponents(token string) (*APIKey, error) {
	parts := strings.Split(token, string(a.tokenSeparator))
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	return &APIKey{
		ShortToken: parts[1],
		LongToken:  parts[2],
		Token:      token,
	}, nil
}

// CheckAPIKey verifies that the hash of the long token in the key matches the provided hash.
func (a *APIKeyGenerator) CheckAPIKey(token, hash string) (bool, error) {
	longToken, err := a.ExtractLongToken(token)
	if err != nil {
		return false, fmt.Errorf("failed to extract long token: %v", err)
	}
	return a.tokenHasher.Verify(longToken, hash), nil
}
