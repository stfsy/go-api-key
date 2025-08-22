package apikey

import "testing"

func FuzzGetTokenComponents(f *testing.F) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "fuzz"})
	f.Add("fuzz#short#long")
	f.Add("badtoken")
	f.Add("fuzz#short")
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = gen.GetTokenComponents(token)
	})
}

func FuzzExtractShortToken(f *testing.F) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "fuzz"})
	f.Add("fuzz#short#long")
	f.Add("badtoken")
	f.Add("fuzz#short")
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = gen.ExtractShortToken(token)
	})
}

func FuzzExtractLongToken(f *testing.F) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "fuzz"})
	f.Add("fuzz#short#long")
	f.Add("badtoken")
	f.Add("fuzz#short")
	f.Fuzz(func(t *testing.T, token string) {
		_, _ = gen.ExtractLongToken(token)
	})
}

func FuzzCheckAPIKey(f *testing.F) {
	gen, _ := NewApiKeyGenerator(ApiKeyGeneratorOptions{TokenPrefix: "fuzz"})
	f.Add("fuzz#short#long", "hash")
	f.Add("badtoken", "hash")
	f.Fuzz(func(t *testing.T, token, hash string) {
		_, _ = gen.CheckAPIKey(token, hash)
	})
}
