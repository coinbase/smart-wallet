package jwt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

func buildLookup(
	api frontend.API,
	expectedPrefix string,
	expectedValue []uints.U8,
) *logderivlookup.Table {
	l := logderivlookup.New(api)
	for _, v := range expectedPrefix {
		l.Insert(v)
	}

	for _, v := range expectedValue {
		l.Insert(v.Val)
	}

	return l
}
