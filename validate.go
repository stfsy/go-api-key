package apikey

// isValidTokenComponent checks that a token component is non-empty and contains only allowed characters.
func isValidTokenComponent(component string) bool {
	if len(component) == 0 {
		return false
	}
	for _, r := range component {
		//nolint:all
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}
