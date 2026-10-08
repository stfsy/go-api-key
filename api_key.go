// Package apikey provides functions to generate and parse Seam-style API keys with base64 encoding.
package apikey

import (
	"bytes"
	"crypto/subtle"
	"fmt"
	"regexp"
	"strings"
)

const (
	defaultShortTokenBytes = 16
	defaultLongTokenBytes  = 64
	defaultTokenSeparator  = '_'
	minShortTokenBytes     = 8
	minLongTokenBytes      = 32
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
	Prefix        string
	ShortToken    string
	LongToken     string
	LongTokenHash string
	Token         string
}

// String implements fmt.Stringer to prevent accidental leakage of secret tokens in logs.
func (k *APIKey) String() string {
	return fmt.Sprintf("APIKey[Prefix: %s, ShortToken: %s, LongToken: [REDACTED]]", k.Prefix, k.ShortToken)
}

// Zeroize deterministically wipes the LongToken and Token memory from RAM.
func (k *APIKey) Zeroize() {
	if k == nil {
		return
	}
	ZeroizeString(&k.LongToken)
	ZeroizeString(&k.Token)
	k.Prefix = ""
	k.ShortToken = ""
	k.LongTokenHash = ""
}

// APIKeyBytes holds the byte-slice components of an API key for zero-heap-string environments.
type APIKeyBytes struct {
	Prefix        []byte
	ShortToken    []byte
	LongToken     []byte // Secret bearer component - do not log
	LongTokenHash string
	Token         []byte
}

// String implements fmt.Stringer to prevent accidental leakage of secret tokens in logs.
func (k *APIKeyBytes) String() string {
	return fmt.Sprintf("APIKeyBytes[Prefix: %s, ShortToken: %s, LongToken: [REDACTED]]", string(k.Prefix), string(k.ShortToken))
}

// Zeroize deterministically overwrites all byte slices with zeros to erase credentials from RAM.
func (k *APIKeyBytes) Zeroize() {
	if k == nil {
		return
	}
	ZeroizeBytes(k.LongToken)
	ZeroizeBytes(k.Token)
	ZeroizeBytes(k.ShortToken)
	ZeroizeBytes(k.Prefix)
	k.LongTokenHash = ""
}

// NewApiKeyGenerator creates a new APIKeyGenerator using options. Id generator and hasher are optional.
func NewApiKeyGenerator(opts ApiKeyGeneratorOptions) (*APIKeyGenerator, error) {
	if len(opts.TokenPrefix) == 0 {
		return nil, fmt.Errorf("token prefix must not be empty")
	}
	tokenSeparator := opts.TokenSeparator
	if tokenSeparator == 0 {
		tokenSeparator = defaultTokenSeparator
	}
	// Regex: only a-zA-Z0-9_- and must not contain the separator
	validPrefix := `^[a-zA-Z0-9_-]{1,8}$`
	matched, err := regexp.MatchString(validPrefix, opts.TokenPrefix)
	if err != nil {
		return nil, fmt.Errorf("token prefix validation failed: %w", err)
	}
	if !matched {
		return nil, fmt.Errorf("token prefix must match %s", validPrefix)
	}
	if strings.ContainsRune(opts.TokenPrefix, tokenSeparator) {
		return nil, fmt.Errorf("token prefix cannot contain the token separator %q", tokenSeparator)
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
	} else if shortTokenBytes < minShortTokenBytes {
		return nil, fmt.Errorf("short token bytes must be at least %d", minShortTokenBytes)
	}
	longTokenBytes := opts.LongTokenBytes
	if longTokenBytes == 0 {
		longTokenBytes = defaultLongTokenBytes
	} else if longTokenBytes < minLongTokenBytes {
		return nil, fmt.Errorf("long token bytes must be at least %d", minLongTokenBytes)
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
		return nil, fmt.Errorf("failed to generate short token: %w", err)
	}
	longToken, err := a.tokenBytesGenerator.Generate(a.longTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate long token: %w", err)
	}
	sep := string(a.tokenSeparator)
	token := fmt.Sprintf("%s%s%s%s%s", a.tokenPrefix, sep, shortToken, sep, longToken)
	hash, err := a.tokenHasher.Hash(longToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash long token: %w", err)
	}
	return &APIKey{
		Prefix:        a.tokenPrefix,
		ShortToken:    shortToken,
		LongToken:     longToken,
		LongTokenHash: hash,
		Token:         token,
	}, nil
}

// GetTokenComponents parses a full API key string into its components.
func (a *APIKeyGenerator) GetTokenComponents(token string) (*APIKey, error) {
	parts := strings.Split(token, string(a.tokenSeparator))
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// iterate over all parts and verify they are valid components
	for _, part := range parts {
		if !isValidTokenComponent(part) {
			return nil, fmt.Errorf("invalid token component: %q", part)
		}
	}

	if subtle.ConstantTimeCompare([]byte(parts[0]), []byte(a.tokenPrefix)) != 1 {
		return nil, fmt.Errorf("token prefix mismatch: %q", parts[0])
	}

	return &APIKey{
		Prefix:     parts[0],
		ShortToken: parts[1],
		LongToken:  parts[2],
		Token:      token,
	}, nil
}

// CheckAPIKey verifies that the hash of the long token in the key matches the provided hash.
// At this point we expect the token to be in valid format e.g. extract via GetTokenComponents.
func (a *APIKeyGenerator) CheckAPIKey(token, hash string) (bool, error) {
	components, err := a.GetTokenComponents(token)
	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}
	return a.tokenHasher.Verify(components.LongToken, hash), nil
}

// GenerateAPIKeyBytes generates a new API key as byte buffers that can be explicitly zeroed out.
func (a *APIKeyGenerator) GenerateAPIKeyBytes() (*APIKeyBytes, error) {
	shortToken, err := a.tokenIdGenerator.Generate(a.shortTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate short token: %w", err)
	}
	longToken, err := a.tokenBytesGenerator.Generate(a.longTokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate long token: %w", err)
	}
	hash, err := a.tokenHasher.Hash(longToken)
	if err != nil {
		return nil, fmt.Errorf("failed to hash long token: %w", err)
	}

	prefixBytes := []byte(a.tokenPrefix)
	shortBytes := []byte(shortToken)
	longBytes := []byte(longToken)
	sep := byte(a.tokenSeparator)

	tokenBytes := make([]byte, 0, len(prefixBytes)+1+len(shortBytes)+1+len(longBytes))
	tokenBytes = append(tokenBytes, prefixBytes...)
	tokenBytes = append(tokenBytes, sep)
	tokenBytes = append(tokenBytes, shortBytes...)
	tokenBytes = append(tokenBytes, sep)
	tokenBytes = append(tokenBytes, longBytes...)

	return &APIKeyBytes{
		Prefix:        prefixBytes,
		ShortToken:    shortBytes,
		LongToken:     longBytes,
		LongTokenHash: hash,
		Token:         tokenBytes,
	}, nil
}

// GetTokenComponentsBytes parses an API key byte slice into its byte components and verifies the prefix.
func (a *APIKeyGenerator) GetTokenComponentsBytes(token []byte) (*APIKeyBytes, error) {
	parts := bytes.Split(token, []byte(string(a.tokenSeparator)))
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	for _, part := range parts {
		if !isValidTokenComponent(string(part)) {
			return nil, fmt.Errorf("invalid token component: %q", part)
		}
	}

	if subtle.ConstantTimeCompare(parts[0], []byte(a.tokenPrefix)) != 1 {
		return nil, fmt.Errorf("token prefix mismatch: %q", parts[0])
	}

	return &APIKeyBytes{
		Prefix:     parts[0],
		ShortToken: parts[1],
		LongToken:  parts[2],
		Token:      token,
	}, nil
}

// CheckAPIKeyBytes verifies that the hash of the long token in the key matches the provided hash.
func (a *APIKeyGenerator) CheckAPIKeyBytes(token []byte, hash string) (bool, error) {
	components, err := a.GetTokenComponentsBytes(token)
	if err != nil {
		return false, fmt.Errorf("failed to parse token: %w", err)
	}
	return a.tokenHasher.Verify(string(components.LongToken), hash), nil
}
