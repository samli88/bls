package bls

import (
	"crypto/sha256"
)

// Hash256 function with 256 bit outputs.
func Hash256(m []byte) []byte {
	h := sha256.New()
	h.Write(m)
	return h.Sum(nil)
}
