# go-api-key

This package provides a simple, extensible API key generator for Go, supporting custom random ID generators and token hashers.

## Features
- Generate API keys with a customizable prefix, short token, and long token.
- Use your own random ID generator and token hasher, or use the secure defaults.
- Parse and validate API keys.

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
	fmt.Println("API Key:", key.Token)

	// Parse and check
	parsed, err := gen.GetTokenComponents(key.Token)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Short: %s, Long: %s, Hash: %s\n", parsed.ShortToken, parsed.LongToken, parsed.LongTokenHash)

	ok, err := gen.CheckAPIKey(key.Token, key.LongTokenHash)
	fmt.Println("Valid:", ok, "Error:", err)
}
```

## Notes

- The token prefix must be 1-8 characters, using only `[a-zA-Z0-9_-]` and must not contain the separator (`#`).
- The default separator is `#`.
- You can provide your own implementations of `RandomBytesGenerator` and `Hasher` for custom behavior/testing.

## API Overview

### Constructors

#### `NewApiKeyGenerator`

```go
func NewApiKeyGenerator(opts ApiKeyGeneratorOptions) (*APIKeyGenerator, error)
```

Create a new API key generator. All options are set via the `ApiKeyGeneratorOptions` struct:

```go
type ApiKeyGeneratorOptions struct {
	TokenPrefix         string // required, 1-8 chars, [a-zA-Z0-9_-], no separator
	TokenSeparator      string // optional, defaults to "#"
	TokenIdGenerator    RandomBytesGenerator // optional, defaults to secure random
	TokenBytesGenerator RandomBytesGenerator // optional, defaults to secure random
	TokenHasher         Hasher               // optional, defaults to SHA256
	ShortTokenBytes     int                  // optional, defaults to 8
	LongTokenBytes      int                  // optional, defaults to 64
}
```

### Interfaces


#### `RandomBytesGenerator`

```go
type RandomBytesGenerator interface {
	Generate(n int) (string, error)
}
```
Default: `DefaultRandomBytesGenerator` (crypto/rand, base64 URL encoding)

#### `Hasher`

```go
type Hasher interface {
	Hash(token string) (string, error)
	Verify(token, hash string) bool
}
```
Default: `Argon2IdHasher` (Argon2id hash string). You can also use `Sha256Hasher` (SHA256 hex string).

### Methods

#### `(*APIKeyGenerator) GenerateAPIKey()`

Generate a new API key:

```go
key, err := gen.GenerateAPIKey()
// key.ShortToken, key.LongToken, key.LongTokenHash, key.Token
```

#### `(*APIKeyGenerator) ExtractShortToken(token string) (string, error)`
#### `(*APIKeyGenerator) ExtractLongToken(token string) (string, error)`
#### `(*APIKeyGenerator) GetTokenComponents(token string) (*APIKey, error)`
#### `(*APIKeyGenerator) CheckAPIKey(token, hash string) (bool, error)`

#### Hashing and Verifying tokens directly

You can use a hasher directly:

```go
hasher := &apikey.Argon2IdHasher{}
hash, err := hasher.Hash("sometoken")
if err != nil {
	panic(err)
}
ok := hasher.Verify("sometoken", hash)
```

## Related Work
- [seamapi/prefixed-api-key](https://github.com/seamapi/prefixed-api-key/tree/main) – inspiration and reference for prefixed API key design.
