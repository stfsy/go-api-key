package apikey

import "testing"

func FuzzIsValidTokenComponent(f *testing.F) {
	// Seed with valid and invalid examples
	f.Add("abcABC123_-") // valid
	f.Add("")            // valid (empty string)
	f.Add("abc def")     // invalid (space)
	f.Add("abc.def")     // invalid (dot)
	f.Add("abc😀def")     // invalid (emoji)
	f.Add("abc#def")     // invalid (hash)
	f.Add("abc\ndef")    // invalid (newline)
	f.Add("abc-def_123") // valid

	f.Fuzz(func(t *testing.T, input string) {
		got := isValidTokenComponent(input)
		// Check that only allowed runes are accepted
		for _, r := range input {
			allowed := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
			if !allowed && got {
				t.Errorf("Accepted invalid rune %q in %q", r, input)
			}
		}
	})
}
