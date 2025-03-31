package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// decodeBase64URL decodes a base64url encoded string into a slice of uint8.
// The input is assumed to be properly base64url encoded and thus MUST be a 4-bytes aligned.
// This function does not error on invalid characters and will simply set the corresponding byte to 0.
func decodeBase64URL(
	api frontend.API,
	field *uints.BinaryField[uints.U32],
	values []uints.U8,
) (res []uints.U8) {
	// The input is assumed to be properly base64url encoded and thus MUST be a 4-bytes aligned.
	for i := range len(values) / 4 {
		first := values[i*4].Val
		second := values[i*4+1].Val
		third := values[i*4+2].Val
		fourth := values[i*4+3].Val
		firstDecoded := decodeValue(api, first)
		secondDecoded := decodeValue(api, second)
		thirdDecoded := decodeValue(api, third)
		fourthDecoded := decodeValue(api, fourth)

		firstDecodedBin := api.ToBinary(firstDecoded, 8)
		secondDecodedBin := api.ToBinary(secondDecoded, 8)
		thirdDecodedBin := api.ToBinary(thirdDecoded, 8)
		fourthDecodedBin := api.ToBinary(fourthDecoded, 8)

		aBin := append(secondDecodedBin[4:6], firstDecodedBin[0:6]...)
		bBin := append(thirdDecodedBin[2:6], secondDecodedBin[0:4]...)
		cBin := append(fourthDecodedBin[0:6], thirdDecodedBin[0:2]...)

		res = append(res,
			field.ByteValueOf(api.FromBinary(aBin...)),
			field.ByteValueOf(api.FromBinary(bBin...)),
			field.ByteValueOf(api.FromBinary(cBin...)),
		)
	}

	return res
}

func decodeValue(api frontend.API, n frontend.Variable) (res frontend.Variable) {
	// 45 (-)
	// 48->57 (0-9)
	// 61 (=)
	// 65->90 (A-Z)
	// 97->122 (a-z)
	// 95 (_) => 63
	isDash := equal(api, n, 45)
	isDigit := api.Mul(
		not(api, lessThan(api, 8, n, 48)), // not below 48
		lessThan(api, 8, n, 58),           // not above 57
	)
	// isEqual := equal(api, n, 61)
	isUpper := api.Mul(
		not(api, lessThan(api, 8, n, 65)), // not below 65
		lessThan(api, 8, n, 91),           // not above 90
	)
	isLower := api.Mul(
		not(api, lessThan(api, 8, n, 97)), // not below 97
		lessThan(api, 8, n, 123),          // not above 122
	)
	isUnderscore := equal(api, n, 95)

	// 45 (-) => 62
	// 48->57 (0-9) => 52->61
	// 61 (=) => 0
	// 65->90 (A-Z) => 0->25
	// 97->122 (a-z) => 26->51
	// 95 (_) => 63
	decodedDash := api.Mul(isDash, 62)
	decodedDigit := api.Mul(isDigit, api.Add(n, 4))
	// decodedEqual := api.Mul(isEqual, 0)
	decodedUpper := api.Mul(isUpper, api.Sub(n, 65))
	decodedLower := api.Mul(isLower, api.Sub(n, 71))
	decodedUnderscore := api.Mul(isUnderscore, 63)

	return api.Add(
		decodedDash,
		decodedDigit,
		// decodedEqual,
		decodedUpper,
		decodedLower,
		decodedUnderscore,
	)
}
