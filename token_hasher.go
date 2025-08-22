package apikey

import (
	"crypto/sha256"
	"fmt"
)

// Hasher defines an interface for hashing a token string.
type Hasher interface {
	Hash(token string) (string, error)
	Verify(token, hash string) bool
}

// Sha256Hasher implements Hasher using SHA256.
type Sha256Hasher struct{}

func (d *Sha256Hasher) Hash(longToken string) (string, error) {
	h := sha256.Sum256([]byte(longToken))
	return fmt.Sprintf("%x", h[:]), nil
}

func (d *Sha256Hasher) Verify(token, hash string) bool {
	h, err := d.Hash(token)
	if err != nil {
		return false
	}
	return h == hash
}
