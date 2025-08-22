package apikey

import (
	"testing"
)

func FuzzSha256Hasher(f *testing.F) {
	hasher := &Sha256Hasher{}
	f.Add("sometoken")
	f.Add("")
	f.Fuzz(func(t *testing.T, token string) {
		hash, err := hasher.Hash(token)
		if err != nil {
			t.Skip()
		}
		_ = hasher.Verify(token, hash)
	})
}

func FuzzArgon2IdHasher(f *testing.F) {
	hasher := &Argon2IdHasher{}
	f.Add("sometoken")
	f.Add("")
	f.Fuzz(func(t *testing.T, token string) {
		hash, err := hasher.Hash(token)
		if err != nil {
			t.Skip()
		}
		_ = hasher.Verify(token, hash)
	})
}
