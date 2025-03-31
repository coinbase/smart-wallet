package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

var expectedTypU8 [len(expectedTypJson)]uints.U8
var expectedAlgU8 [len(expectedAlgJson)]uints.U8
var expectedCrvU8 [len(expectedCrvJson)]uints.U8
var expectedKidPrefixU8 [len(expectedKidPrefixJson)]uints.U8

var commaU8 uints.U8
var closeBraceU8 uints.U8

func init() {
	for i, b := range expectedTypJson {
		expectedTypU8[i] = uints.NewU8(uint8(b))
	}

	for i, b := range expectedAlgJson {
		expectedAlgU8[i] = uints.NewU8(uint8(b))
	}

	for i, b := range expectedCrvJson {
		expectedCrvU8[i] = uints.NewU8(uint8(b))
	}

	for i, b := range expectedKidPrefixJson {
		expectedKidPrefixU8[i] = uints.NewU8(uint8(b))
	}

	commaU8 = uints.NewU8(',')
	closeBraceU8 = uints.NewU8('}')
}

func ProcessHeader(
	api frontend.API, field *uints.BinaryField[uints.U32], json []uints.U8,
	typeOffset, algOffset, crvOffset frontend.Variable,
	kidOffset, kidValueLen frontend.Variable,
) {
	byteLenTyp := len(expectedTypU8)
	endTyp := api.Add(typeOffset, byteLenTyp)

	byteLenAlg := len(expectedAlgU8)
	endAlg := api.Add(algOffset, byteLenAlg)

	byteLenCrv := len(expectedCrvU8)
	endCrv := api.Add(crvOffset, byteLenCrv)

	byteLenKidPrefix := len(expectedKidPrefixU8)
	endKidPrefix := api.Add(kidOffset, byteLenKidPrefix)
	endKid := api.Add(endKidPrefix, kidValueLen)
	api.Println("endKid", endKid)

	// extractedKidValue := make([]uints.U8, MaxJwtHeaderKidLen)
	// api.Println("extractedKidValue", extractedKidValue)

	for i := range json {
		// Check the `"typ":"JWT"`
		checkByte(api, json, expectedTypU8[:], i, typeOffset, endTyp)
		checkSeparator(api, json, i, endTyp)

		// Check the `"alg":"ES256"`
		checkByte(api, json, expectedAlgU8[:], i, algOffset, endAlg)
		checkSeparator(api, json, i, endAlg)

		// Check the `"crv":"P-256"`
		checkByte(api, json, expectedCrvU8[:], i, crvOffset, endCrv)
		checkSeparator(api, json, i, endCrv)

		// Check the `"kid":`
		checkByte(api, json, expectedKidPrefixU8[:], i, kidOffset, endKidPrefix)

		// // Check the "kid" value.
		// extractByte(api, field, json, extractedKidValue, i, endKidPrefix, endKid)
		// checkSeparator(api, json, i, endKid)
	}
}

func checkByte(
	api frontend.API,
	json []uints.U8,
	expectedBytes []uints.U8,
	i int,
	rangeStart, rangeEnd frontend.Variable,
) {
	// Get the byte from the JWT JSON.
	b := json[i].Val

	// rangeStart <= i < rangeEnd
	shouldParse := api.Mul(
		not(api, lessThan(api, 16, i, rangeStart)), // i >= rangeStart
		lessThan(api, 16, i, rangeEnd),             // i < rangeEnd
	)

	// Get the corresponding expected byte from the `expected` bytes.
	expectedByte := byteAt(
		api,
		expectedBytes[:],
		api.Sub(i, rangeStart), // NOTE: It is fine to underflow here.
	)

	// assert(shouldParse == 0 || b == expectedByte)
	api.AssertIsDifferent(
		0,
		api.Add(
			equal(api, shouldParse, 0),
			equal(api, b, expectedByte),
		),
	)

}

func checkSeparator(
	api frontend.API,
	json []uints.U8,
	i int,
	end frontend.Variable,
) {
	// Get the byte from the JWT JSON.
	b := json[i].Val

	// i == end
	shouldBeSeparator := equal(api, i, end)

	// assert(isSeparator == 0 || (b == commaU8 || b == closeBraceU8))
	api.AssertIsDifferent(
		0,
		api.Add(
			equal(api, shouldBeSeparator, 0),
			api.Add(
				equal(api, b, commaU8.Val),
				equal(api, b, closeBraceU8.Val),
			),
		),
	)
}

func extractByte(
	api frontend.API,
	field *uints.BinaryField[uints.U32],
	src []uints.U8,
	dst []uints.U8,
	i int,
	rangeStart, rangeEnd frontend.Variable,
) {
	// Get the byte from the `src` slice.
	b := src[i].Val

	// rangeStart <= i < rangeEnd
	shouldExtract := api.Mul(
		not(api, lessThan(api, 16, i, rangeStart)), // i >= rangeStart
		lessThan(api, 16, i, rangeEnd),             // i < rangeEnd
	)

	// The index to write the byte to in the `dst` slice.
	writeIndex := api.Sub(i, rangeStart) // NOTE: It is fine to underflow here.

	for i := range dst {
		dst[i] = field.ByteValueOf(
			api.Add(
				dst[i],
				api.Mul(
					shouldExtract,
					api.Mul(
						equal(api, i, writeIndex),
						b,
					),
				),
			),
		)
	}
}

// byteAt returns `bytes[atIndex]`. NOTE: If `atIndex` is out of bounds, it will return 0.
func byteAt(
	api frontend.API,
	bytes []uints.U8,
	atIndex frontend.Variable,
) frontend.Variable {

	expected := frontend.Variable(0)
	for i := range bytes {
		expected = api.Add(
			expected,
			api.Mul(
				equal(api, atIndex, i),
				bytes[i].Val,
			),
		)
	}

	return expected
}
