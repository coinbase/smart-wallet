package utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

// Base64URLEncoding maps base64 indices to their corresponding ASCII values
var base64URLEncoding = map[int]int{
	// 0-25 => A-Z (65-90)
	0: 65, 1: 66, 2: 67, 3: 68, 4: 69, 5: 70, 6: 71, 7: 72, 8: 73, 9: 74,
	10: 75, 11: 76, 12: 77, 13: 78, 14: 79, 15: 80, 16: 81, 17: 82, 18: 83, 19: 84,
	20: 85, 21: 86, 22: 87, 23: 88, 24: 89, 25: 90,
	// 26-51 => a-z (97-122)
	26: 97, 27: 98, 28: 99, 29: 100, 30: 101, 31: 102, 32: 103, 33: 104, 34: 105, 35: 106,
	36: 107, 37: 108, 38: 109, 39: 110, 40: 111, 41: 112, 42: 113, 43: 114, 44: 115, 45: 116,
	46: 117, 47: 118, 48: 119, 49: 120, 50: 121, 51: 122,
	// 52-61 => 0-9 (48-57)
	52: 48, 53: 49, 54: 50, 55: 51, 56: 52, 57: 53, 58: 54, 59: 55, 60: 56, 61: 57,
	// Special characters
	62: 45, // - (dash)
	63: 95, // _ (underscore)
}

type Base64Encoder struct {
	api    frontend.API
	lookup *logderivlookup.Table
}

func NewBase64Encoder(api frontend.API) *Base64Encoder {
	lookup := logderivlookup.New(api)
	for k := range len(base64URLEncoding) {
		lookup.Insert(base64URLEncoding[k])
	}

	return &Base64Encoder{
		api:    api,
		lookup: lookup,
	}
}

func (e *Base64Encoder) EncodeBase64URL(bytes []uints.U8) (res []frontend.Variable) {
	bitLen := len(bytes) * 8

	// Loop over the input bytes and store them in big endian (msb first)
	var bins []frontend.Variable
	for _, value := range bytes {
		bin := e.api.ToBinary(value.Val, 8)
		for i := range 8 {
			bins = append(bins, bin[7-i])
		}
	}

	// Consume the bin values by chunk of 6 and decode them to base64
	for i := 0; i < bitLen; i += 6 {
		var bitsForValue []frontend.Variable
		for j := range 6 {
			bitsForValue = append(bitsForValue, bins[i+(5-j)])
		}
		v := e.api.FromBinary(bitsForValue...)
		encoded := e.lookup.Lookup(v)[0]
		res = append(res, encoded)
	}

	return res
}
