package apikey

import "testing"

func TestIsValidTokenComponent(t *testing.T) {
	cases := []struct {
		input string
		want  bool
		desc  string
	}{
		{"abcABC123_-", true, "all allowed chars"},
		{"", true, "empty string (allowed)"},
		{"a", true, "single allowed char"},
		{"-_-_-_-_", true, "only dashes and underscores"},
		{"abc def", false, "contains space"},
		{"abc.def", false, "contains dot"},
		{"abc@def", false, "contains at"},
		{"abc#def", false, "contains hash"},
		{"abc$def", false, "contains dollar"},
		{"abc/def", false, "contains slash"},
		{"abc\\def", false, "contains backslash"},
		{"abc😀def", false, "contains emoji"},
		{"abc\n", false, "contains newline"},
		{"abc	def", false, "contains tab"},
		{"abc-def_123", true, "mixed allowed"},
		{"abcDEF!", false, "contains exclamation"},
		{"1234567890", true, "all digits"},
		{"A_B-C_D-E", true, "mixed case and symbols"},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			got := isValidTokenComponent(tc.input)
			if got != tc.want {
				t.Errorf("isValidTokenComponent(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
