package main

// xor all arguments together
// stolen from https://groups.google.com/d/topic/golang-nuts/m7tTO2jnXG4/discussion
func xor_bytes(b1 []byte, bmore ...[]byte) []byte {
	for _, m := range bmore {
		if len(b1) != len(m) {
			panic("length mismatch")
		}
	}

	rv := make([]byte, len(b1))

	for i := range b1 {
		rv[i] = b1[i]
		for _, m := range bmore {
			rv[i] = rv[i] ^ m[i]
		}
	}

	return rv
}

