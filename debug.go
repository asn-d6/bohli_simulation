package main

import (
	"log"
)

// https://groups.google.com/forum/#!topic/golang-nuts/ct99dtK2Jo4
const debug debugging = false

type debugging bool

func (d debugging) Printf(format string, args ...interface{}) {
        if d {
        log.Printf(format, args...)
    }
}
