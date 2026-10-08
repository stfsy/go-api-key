# go-api-key

This package provides a simple, extensible API key generator for Go, supporting custom random ID generators and token hashers.

## Features
- Generate API keys with a customizable prefix, short token, and long token.
- Use your own random ID generator and token hasher, or use the secure defaults.
- Parse and validate API keys.

## Usage
- Use the library to create an API key. 
- Store the `ShortToken` and the `LongTokenHash` in your database.
- Send the `LongToken` to the user / client.

## Installation

```sh
go get github.com/stfsy/go-api-key
```

## Example

```go
package main

import (
	"fmt"
	"github.com/stfsy/go-api-key"
)

func main() {
	// Create a generator with default secure random and Argon2id hasher
	gen, err := apikey.NewApiKeyGenerator(apikey.ApiKeyGeneratorOptions{
		TokenPrefix: "mycorp",
		// Optionally:
		// TokenSeparator:      '_', // defaults to '_'
		// TokenIdGenerator:    &apikey.DefaultRandomBytesGenerator{},
		// TokenBytesGenerator: &apikey.DefaultRandomBytesGenerator{},
		// TokenHasher:         &apikey.Sha256Hasher{}, // or &apikey.Argon2IdHasher{}
	})
	if err != nil {
		panic(err)
	}

	// Generate a new API key
	key, err := gen.GenerateAPIKey()
	if err != nil {
		panic(err)
	}
	// Zeroize secret memory from RAM when finished
	defer key.Zeroize()

	// APIKey implements fmt.Stringer, redacting the secret LongToken in logs:
	fmt.Println("Generated key:", key) // Prints: APIKey[Prefix: mycorp, ShortToken: ..., LongToken: [REDACTED]]

	// Safe handling:
	// - Store key.ShortToken (indexed lookup) and key.LongTokenHash in your database.
	// - Return key.Token to the client ONCE. Do NOT write key.LongToken or key.Token to application logs!

	// Parse and check incoming token:
	parsed, err := gen.GetTokenComponents(key.Token)
	if err != nil {
		panic(err)
	}
	defer parsed.Zeroize()
	fmt.Printf("Prefix: %s, Short: %s\n", parsed.Prefix, parsed.ShortToken)

	ok, err := gen.CheckAPIKey(key.Token, key.LongTokenHash)
	fmt.Println("Valid:", ok, "Error:", err)
}
```

### High-Assurance Byte-Oriented Workflow (Zero-Heap Strings)

For security-sensitive environments (FIPS, PCI-DSS) that require deterministic memory zeroing and avoiding immutable Go string retention on the heap:

```go
// Generate key directly into byte buffers
keyBytes, err := gen.GenerateAPIKeyBytes()
if err != nil {
    panic(err)
}
defer keyBytes.Zeroize() // Overwrites LongToken, Token, and ShortToken buffers with zeros

// Parse and check using byte slices
parsedBytes, err := gen.GetTokenComponentsBytes(keyBytes.Token)
if err != nil {
    panic(err)
}
defer parsedBytes.Zeroize()

ok, err := gen.CheckAPIKeyBytes(keyBytes.Token, keyBytes.LongTokenHash)
```

## Security & Architecture Notes
- **Prefix Verification:** `GetTokenComponents` and `CheckAPIKey` strictly verify that the token's prefix matches the generator's configured prefix using constant-time comparison, preventing cross-environment (e.g. test vs. prod) credential confusion.
- **Strict Component Validation:** All token components (prefix, short token, long token) must be non-empty and contain only allowed characters `[a-zA-Z0-9_-]`.
- **Default Separator:** The default separator is `_` (underscore). Using `_` avoids URI fragment truncation in URLs and shell comment parsing issues associated with `#`. The prefix must not contain the separator.
- **Cryptographic Minimums:** `ShortTokenBytes` must be at least 8 bytes (default: 16). `LongTokenBytes` must be at least 32 bytes (default: 64) to ensure high entropy ($2^{256}$+ security margin).
- **Secret Redaction:** `APIKey.String()` and `APIKeyBytes.String()` mask `LongToken` as `[REDACTED]` to mitigate sensitive data exposure in logs (CWE-532).
- **Memory Zeroization (OWASP ASVS V2.10.4 / CWE-226):** `APIKey.Zeroize()` and `APIKeyBytes.Zeroize()` overwrite sensitive credentials in RAM using compiler-safe barriers (`ZeroizeBytes`, `ZeroizeString`), minimizing the window of exposure to core dumps, heap inspection, and swap space.

## API Overview

### Constructors

#### `NewApiKeyGenerator`

```go
func NewApiKeyGenerator(opts ApiKeyGeneratorOptions) (*APIKeyGenerator, error)
```

Create a new API key generator. All options are set via the `ApiKeyGeneratorOptions` struct:

```go
type ApiKeyGeneratorOptions struct {
	TokenPrefix         string               // required, 1-8 chars, [a-zA-Z0-9_-], no separator
	TokenSeparator      rune                 // optional, defaults to '_'
	TokenIdGenerator    RandomBytesGenerator // optional, defaults to secure random
	TokenBytesGenerator RandomBytesGenerator // optional, defaults to secure random
	TokenHasher         Hasher               // optional, defaults to Argon2IdHasher
	ShortTokenBytes     int                  // optional, defaults to 16 (min 8)
	LongTokenBytes      int                  // optional, defaults to 64 (min 32)
}
```

### Data Structures

#### `APIKey`

```go
type APIKey struct {
	Prefix        string // public domain prefix
	ShortToken    string // public lookup ID
	LongToken     string // secret bearer token (do not log)
	LongTokenHash string // stored cryptographic hash
	Token         string // full bearer key (<prefix>_<short>_<long>)
}

// Zeroize wipes secret memory in RAM and resets fields
func (k *APIKey) Zeroize()
```

#### `APIKeyBytes`

```go
type APIKeyBytes struct {
	Prefix        []byte // public domain prefix
	ShortToken    []byte // public lookup ID
	LongToken     []byte // secret bearer token (do not log)
	LongTokenHash string // stored cryptographic hash
	Token         []byte // full bearer key (<prefix>_<short>_<long>)
}

// Zeroize overwrites all underlying byte slices with zeros
func (k *APIKeyBytes) Zeroize()
```

### Zeroization Utilities

```go
// Overwrites byte slice with zeros using compiler-safe write barrier
func ZeroizeBytes(b []byte)

// Overwrites backing array of heap-allocated string and clears string
func ZeroizeString(s *string)
```

### Interfaces

#### `RandomBytesGenerator`

```go
type RandomBytesGenerator interface {
	Generate(n int) (string, error)
}
```
Default: `DefaultRandomBytesGenerator` (crypto/rand, base64 URL encoding, separator-safe)

#### `Hasher`

```go
type Hasher interface {
	Hash(token string) (string, error)
	Verify(token, hash string) bool
}
```
Default: `Argon2IdHasher` (Argon2id hash string). You can also use `Sha256Hasher` (SHA256 hex string).

### Methods

#### String API

- `(*APIKeyGenerator) GenerateAPIKey() (*APIKey, error)`: Generates a new API key.
- `(*APIKeyGenerator) GetTokenComponents(token string) (*APIKey, error)`: Parses the token, validates all components are non-empty, and verifies prefix match.
- `(*APIKeyGenerator) CheckAPIKey(token, hash string) (bool, error)`: Verifies format and validates hash match.

#### Byte Slice API (High-Assurance / Zero-Heap Strings)

- `(*APIKeyGenerator) GenerateAPIKeyBytes() (*APIKeyBytes, error)`: Generates a new API key as byte buffers.
- `(*APIKeyGenerator) GetTokenComponentsBytes(token []byte) (*APIKeyBytes, error)`: Parses and validates key byte slice.
- `(*APIKeyGenerator) CheckAPIKeyBytes(token []byte, hash string) (bool, error)`: Verifies format and validates hash match against byte slice.

## Related Work
- [seamapi/prefixed-api-key](https://github.com/seamapi/prefixed-api-key/tree/main) – inspiration and reference for prefixed API key design.
