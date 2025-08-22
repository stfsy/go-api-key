package apikey

import (
	"fmt"

	"github.com/stfsy/go-argon2id"
)

// Argon2IdHasher implements Hasher.
type Argon2IdHasher struct{}

var params = &argon2id.Params{
	Memory:      32 * 1024,
	Iterations:  5,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   64,
}

func (d *Argon2IdHasher) Hash(longToken string) (string, error) {
	hash, err := argon2id.CreateHash(longToken, params)
	if err != nil {
		return "", fmt.Errorf("argon2id.CreateHash failed: %v", err)
	}
	return hash, nil
}

func (d *Argon2IdHasher) Verify(token, hash string) bool {
	ok, err := argon2id.ComparePasswordAndHash(token, hash)
	if err != nil {
		return false
	}
	return ok
}
