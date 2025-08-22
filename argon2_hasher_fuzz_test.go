package apikey

import "testing"

func FuzzArgon2IdHasher_HashAndVerify(f *testing.F) {
	hasher := &Argon2IdHasher{}
	f.Add("averylongtokenthatmightcauseissuesifnothandledcorrectlyorjusttestingbutwewanttoensureitworks")
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
