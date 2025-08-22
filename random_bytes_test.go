package apikey

import (
	"encoding/base64"
	"testing"
)

func TestDefaultRandomBytesGenerator_Generate(t *testing.T) {
	gen := &DefaultRandomBytesGenerator{}
	lengths := []int{1, 8, 32, 64}
	for _, n := range lengths {
		str, err := gen.Generate(n)
		if err != nil {
			t.Errorf("Generate(%d) returned error: %v", n, err)
		}
		// Decode to check length
		decoded, err := base64.RawURLEncoding.DecodeString(str)
		if err != nil {
			t.Errorf("base64 decode failed for n=%d: %v", n, err)
		}
		if len(decoded) != n {
			t.Errorf("expected %d bytes, got %d", n, len(decoded))
		}
	}
}
