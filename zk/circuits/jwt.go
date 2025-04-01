package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

var expectedTypU8 [len(ExpectedTypJson)]uints.U8
var expectedAlgU8 [len(ExpectedAlgJson)]uints.U8
var expectedKidPrefixU8 [len(ExpectedKidPrefixJson)]uints.U8

var expectedIssPrefixU8 [len(ExpectedIssPrefixJson)]uints.U8
var expectedAudPrefixU8 [len(ExpectedAudPrefixJson)]uints.U8
var expectedSubPrefixU8 [len(ExpectedSubPrefixJson)]uints.U8

var commaU8 uints.U8
var closeBraceU8 uints.U8

func init() {
	for i := range ExpectedTypJson {
		expectedTypU8[i] = uints.NewU8(uint8(ExpectedTypJson[i]))
		expectedAlgU8[i] = uints.NewU8(uint8(ExpectedAlgJson[i]))
	}

	for i := range ExpectedKidPrefixJson {
		expectedKidPrefixU8[i] = uints.NewU8(uint8(ExpectedKidPrefixJson[i]))
		expectedIssPrefixU8[i] = uints.NewU8(uint8(ExpectedIssPrefixJson[i]))
		expectedAudPrefixU8[i] = uints.NewU8(uint8(ExpectedAudPrefixJson[i]))
		expectedSubPrefixU8[i] = uints.NewU8(uint8(ExpectedSubPrefixJson[i]))
	}

	commaU8 = uints.NewU8(',')
	closeBraceU8 = uints.NewU8('}')
}

func ProcessJwtHeader(
	api frontend.API, json []uints.U8,
	typeOffset, algOffset frontend.Variable,
	kidOffset, kidValueLen frontend.Variable,
	expectedKidValue []uints.U8,
) {
	byteLenTyp := len(expectedTypU8)
	endTyp := api.Add(typeOffset, byteLenTyp)

	byteLenAlg := len(expectedAlgU8)
	endAlg := api.Add(algOffset, byteLenAlg)

	byteLenKidPrefix := len(expectedKidPrefixU8)
	endKidPrefix := api.Add(kidOffset, byteLenKidPrefix)
	endKid := api.Add(endKidPrefix, kidValueLen)

	for i := range json {
		// Check the `"typ":"JWT"`
		checkByte(api, json, expectedTypU8[:], i, typeOffset, endTyp)
		checkSeparator(api, json, i, endTyp)

		// Check the `"alg":"ES256"`
		checkByte(api, json, expectedAlgU8[:], i, algOffset, endAlg)
		checkSeparator(api, json, i, endAlg)

		// Check the `"kid":`
		checkByte(api, json, expectedKidPrefixU8[:], i, kidOffset, endKidPrefix)
		checkSeparator(api, json, i, endKid)

		// Check the "kid" value.
		checkByte(api, json, expectedKidValue[:], i, endKidPrefix, endKid)
	}
}

func ProcessJwtPayload(
	api frontend.API, field *uints.BinaryField[uints.U32], json []uints.U8,
	issOffset, issValueLen frontend.Variable,
	audOffset, audValueLen frontend.Variable,
	subOffset, subValueLen frontend.Variable,
) (iss [MaxJwtPayloadIssLen]uints.U8, aud [MaxJwtPayloadAudLen]uints.U8, sub [MaxJwtPayloadSubLen]uints.U8) {

	byteLenIssPrefix := len(expectedIssPrefixU8)
	endIssPrefix := api.Add(issOffset, byteLenIssPrefix)
	endIss := api.Add(endIssPrefix, issValueLen)
	api.Println("issOffset", issOffset)
	api.Println("issValueLen", issValueLen)
	api.Println("endIssPrefix", endIssPrefix)
	api.Println("endIss", endIss)

	byteLenAudPrefix := len(expectedAudPrefixU8)
	endAudPrefix := api.Add(audOffset, byteLenAudPrefix)
	endAud := api.Add(endAudPrefix, audValueLen)
	api.Println("endAud", endAud)

	byteLenSubPrefix := len(expectedSubPrefixU8)
	endSubPrefix := api.Add(subOffset, byteLenSubPrefix)
	endSub := api.Add(endSubPrefix, subValueLen)
	api.Println("endSub", endSub)

	for i := range iss {
		iss[i] = uints.NewU8(0)
	}

	for i := range aud {
		aud[i] = uints.NewU8(0)
	}

	for i := range sub {
		sub[i] = uints.NewU8(0)
	}

	for i := range json {
		// Check and extract the "iss" value.
		checkByte(api, json, expectedIssPrefixU8[:], i, issOffset, endIssPrefix)
		checkSeparator(api, json, i, endIss)
		extractByte(api, field, json, iss[:], i, endIssPrefix, endIss)

		// Check and extract the "aud" value.
		checkByte(api, json, expectedAudPrefixU8[:], i, audOffset, endAudPrefix)
		extractByte(api, field, json, aud[:], i, endAudPrefix, endAud)
		checkSeparator(api, json, i, endAud)

		// Check and extract the "sub" value.
		checkByte(api, json, expectedSubPrefixU8[:], i, subOffset, endSubPrefix)
		extractByte(api, field, json, sub[:], i, endSubPrefix, endSub)
		checkSeparator(api, json, i, endSub)
	}

	return sub, iss, aud
}

func PackJwt(
	api frontend.API,
	field *uints.BinaryField[uints.U32],
	header []uints.U8,
	payload []uints.U8,
	jwtHeaderBase64Len, jwtPayloadBase64Len frontend.Variable,
) (res []uints.U8) {
	buffer, err := NewBuffer(api, MaxJwtBase64Len)
	if err != nil {
		return nil
	}
	buffer.AppendVariable(header, 100, jwtHeaderBase64Len)
	buffer.AppendByte(field.ByteValueOf('.'))
	buffer.AppendVariable(payload, 500, jwtPayloadBase64Len)
	return buffer.data
	//res = make([]uints.U8, MaxJwtBase64Len)
	//for i := range res {
	//	isHeader := 1 //lessThan(api, 16, i, jwtHeaderBase64Len)
	//	isDot := equal(api, i, jwtHeaderBase64Len)
	//	isPayload := api.Mul(
	//		not(api, isHeader),
	//		not(api, isDot),
	//	)
	//
	//	headerIndex := i
	//	payloadIndex := api.Sub(i, api.Add(jwtHeaderBase64Len, 1)) // +1 for the dot.
	//
	//	v := api.Add(
	//		api.Mul(isHeader, byteAt(api, header, headerIndex)),
	//		api.Mul(isDot, '.'),
	//		api.Mul(isPayload, byteAt(api, payload, payloadIndex)),
	//	)
	//
	//	res[i] = field.ByteValueOf(v)
	//}
	//
	//return res
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
		expectedBytes,
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
	api.Println("b", b)

	// i == end
	shouldBeSeparator := equal(api, i, end)
	api.Println("shouldBeSeparator", shouldBeSeparator)

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
				dst[i].Val,
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

	b := frontend.Variable(0)

	for i := range bytes {
		b = api.Add(
			b,
			api.Mul(
				equal(api, atIndex, i),
				bytes[i].Val,
			),
		)
	}

	return b
}
