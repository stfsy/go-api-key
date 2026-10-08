package apikey

import (
	"crypto/subtle"
	"unsafe"
)

// ZeroizeBytes overwrites a byte slice with zeros in a manner that the compiler
// cannot eliminate through dead-store elimination optimizations.
func ZeroizeBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	zeros := make([]byte, len(b))
	subtle.ConstantTimeCopy(1, b, zeros)
}

// ZeroizeString overwrites the backing memory of a heap-allocated string with zeros
// and resets the string reference to empty.
//
// CAUTION: This directly mutates the underlying string buffer using unsafe. Only call this
// on dynamically allocated strings (such as generated API keys), never on string constants
// or interned strings residing in read-only memory segments.
func ZeroizeString(s *string) {
	if s == nil || len(*s) == 0 {
		return
	}
	// Safely obtain a mutable slice over the backing array
	strBytes := unsafe.Slice(unsafe.StringData(*s), len(*s))
	ZeroizeBytes(strBytes)
	*s = ""
}
