package apikey

import "testing"

func FuzzGetTokenComponents(f *testing.F) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "fuzz"})
	f.Add("fuzz_short_long")
	f.Add("badtoken")
	f.Add("fuzz_short")
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = gen.GetTokenComponents(token)
	})
}

func FuzzCheckAPIKey(f *testing.F) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "fuzz"})
	f.Add("fuzz_short_long", "hash")
	f.Add("badtoken", "hash")
	f.Fuzz(func(t *testing.T, token, hash string) {
		_, _ = gen.CheckAPIKey(token, hash)
	})
}
