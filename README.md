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
	// Create a generator with default secure random and SHA256 hasher
	gen, err := apikey.NewApiKeyGenerator(apikey.ApiKeyGeneratorOptions{
		Prefix: "mycompany",
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

- The prefix must be 1-32 characters, using only `[a-zA-Z0-9_-]` and must not contain the separator (`#`).
- The default separator is `#`.
- You can provide your own implementations of `RandomIdGenerator` and `TokenHasher` for custom behavior/testing.

## API Overview

### Constructors

#### `NewApiKeyGenerator`

```go
func NewApiKeyGenerator(opts ApiKeyGeneratorOptions) (*APIKeyGenerator, error)
```

Create a new API key generator. All options are set via the `ApiKeyGeneratorOptions` struct:

```go
type ApiKeyGeneratorOptions struct {
	Prefix            string // required, 1-32 chars, [a-zA-Z0-9_-], no separator
	RandomIdGenerator RandomIdGenerator // optional, defaults to secure random
	TokenHasher       TokenHasher       // optional, defaults to SHA256
}
```

### Interfaces

#### `RandomIdGenerator`

```go
type RandomIdGenerator interface {
	Generate(n int) (string, error)
}
```
Default: `DefaultRandomIdGenerator` (crypto/rand, base64 URL encoding)

#### `TokenHasher`

```go
type TokenHasher interface {
	Hash(token string) string
}
```
Default: `Sha256Hasher` (SHA256 hex string)

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
