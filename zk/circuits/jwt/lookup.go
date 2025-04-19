package jwt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

// buildLookup creates a lookup table for JWT field validation.
func buildLookup(
	api frontend.API,
	compileTimePrefix string,
	runtimeValue []uints.U8,
) *logderivlookup.Table {
	l := logderivlookup.New(api)
	for _, v := range compileTimePrefix {
		l.Insert(v)
	}

	for _, v := range runtimeValue {
		l.Insert(v.Val)
	}

	return l
}
