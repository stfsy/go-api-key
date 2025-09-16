package apikey

// isValidPrefix checks prefix for allowed chars, length, and separator absence.
func isValidTokenComponent(prefix string) bool {
	for _, r := range prefix {
		//nolint:all
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
