package apikey

import (
	"crypto/sha256"
	"fmt"
)

// Hasher defines an interface for hashing a token string.
type Hasher interface {
	Hash(token string) string
}

// Sha256Hasher implements TokenHasher using SHA256.
type Sha256Hasher struct{}

func (d *Sha256Hasher) Hash(longToken string) string {
	h := sha256.Sum256([]byte(longToken))
	return fmt.Sprintf("%x", h[:])
}
