package apikey

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// RandomBytesGenerator defines an interface for generating random IDs as a string.
type RandomBytesGenerator interface {
	Generate(n int) (string, error)
}

// DefaultRandomBytesGenerator implements RandomBytesGenerator using crypto/rand and base64.
// It avoids producing the default token separator ('_') while remaining 100% valid RawURLEncoding.
type DefaultRandomBytesGenerator struct{}

func (d *DefaultRandomBytesGenerator) Generate(n int) (string, error) {
	b := make([]byte, n)
	// Fill b in 3-byte chunks using rejection sampling so base64 never produces '_'
	for i := 0; i < n; i += 3 {
		chunkSize := 3
		if i+chunkSize > n {
			chunkSize = n - i
		}
		for {
			if _, err := rand.Read(b[i : i+chunkSize]); err != nil {
				return "", fmt.Errorf("failed to read random bytes: %w", err)
			}
			chunkStr := base64.RawURLEncoding.EncodeToString(b[i : i+chunkSize])
			if !strings.ContainsRune(chunkStr, '_') {
				break
			}
		}
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
