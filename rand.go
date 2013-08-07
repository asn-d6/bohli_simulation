package main

import (
	"io"
	"crypto/rand"
	"math/big"
)

// generate sizeof(buf) random bytes and turn them into a big.Int
// XXX is this correct?
func rand_int(max *big.Int) *big.Int {
	int, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic("otr: rand.Int() failed!")
	}

	return int
}

// generate sizeof(buf) random bytes and turn them into a big.Int
func rand_bytes(buf []byte) []byte {
	// XXX is this correct? why not use rand.Read()?
	_, err := io.ReadFull(rand.Reader, buf)
	if err != nil {
		panic("otr: short read from random source")
	}

	return buf
}


