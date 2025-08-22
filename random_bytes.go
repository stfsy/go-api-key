package apikey

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// RandomBytesGenerator defines an interface for generating random IDs as a string.
type RandomBytesGenerator interface {
	Generate(n int) (string, error)
}

// DefaultRandomBytesGenerator implements RandomIdGenerator using crypto/rand and base64.
type DefaultRandomBytesGenerator struct{}

func (d *DefaultRandomBytesGenerator) Generate(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("failed to read random bytes: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
