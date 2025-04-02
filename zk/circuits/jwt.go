package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

type JwtVerifier struct {
	api   frontend.API
	field *uints.BinaryField[uints.U32]

	commaU8      uints.U8
	closeBraceU8 uints.U8

	// Header lookup tables.
	typLookup       *logderivlookup.Table
	algLookup       *logderivlookup.Table
	kidPrefixLookup *logderivlookup.Table

	// Payload lookup tables.
	issPrefixLookup *logderivlookup.Table
	audPrefixLookup *logderivlookup.Table
	subPrefixLookup *logderivlookup.Table
}

func NewJwtVerifier(api frontend.API, field *uints.BinaryField[uints.U32]) *JwtVerifier {
	typLookup := logderivlookup.New(api)
	for _, v := range ExpectedTypJson {
		typLookup.Insert(v)
	}

	algLookup := logderivlookup.New(api)
	for _, v := range ExpectedAlgJson {
		algLookup.Insert(v)
	}

	kidPrefixLookup := logderivlookup.New(api)
	for _, v := range ExpectedKidPrefixJson {
		kidPrefixLookup.Insert(v)
	}

	issPrefixLookup := logderivlookup.New(api)
	for _, v := range ExpectedIssPrefixJson {
		issPrefixLookup.Insert(v)
	}

	audPrefixLookup := logderivlookup.New(api)
	for _, v := range ExpectedAudPrefixJson {
		audPrefixLookup.Insert(v)
	}

	subPrefixLookup := logderivlookup.New(api)
	for _, v := range ExpectedSubPrefixJson {
		subPrefixLookup.Insert(v)
	}

	return &JwtVerifier{
		api:   api,
		field: field,

		commaU8:      uints.NewU8(','),
		closeBraceU8: uints.NewU8('}'),

		// Header lookup tables.
		typLookup:       typLookup,
		algLookup:       algLookup,
		kidPrefixLookup: kidPrefixLookup,

		// Payload lookup tables.
		issPrefixLookup: issPrefixLookup,
		audPrefixLookup: audPrefixLookup,
		subPrefixLookup: subPrefixLookup,
	}
}

func (v *JwtVerifier) ProcessJwtHeader(
	json []uints.U8,
	typeOffset, algOffset frontend.Variable,
	kidOffset, kidValueLen frontend.Variable,
	expectedKidValue []uints.U8,
) {
	byteLenTyp := len(ExpectedTypJson)
	endTyp := v.api.Add(typeOffset, byteLenTyp)

	byteLenAlg := len(ExpectedAlgJson)
	endAlg := v.api.Add(algOffset, byteLenAlg)

	byteLenKidPrefix := len(ExpectedKidPrefixJson)
	endKidPrefix := v.api.Add(kidOffset, byteLenKidPrefix)
	endKid := v.api.Add(endKidPrefix, kidValueLen)

	kidValueLookup := logderivlookup.New(v.api)
	for _, v := range expectedKidValue {
		kidValueLookup.Insert(v.Val)
	}

	for i := range json {
		// Check the `"typ":"JWT"`
		v.checkByte(json, v.typLookup, i, typeOffset, endTyp)
		v.checkSeparator(json, i, endTyp)

		// Check the `"alg":"ES256"`
		v.checkByte(json, v.algLookup, i, algOffset, endAlg)
		v.checkSeparator(json, i, endAlg)

		// Check the `"kid":`
		v.checkByte(json, v.kidPrefixLookup, i, kidOffset, endKidPrefix)
		v.checkSeparator(json, i, endKid)

		// Check the "kid" value.
		v.checkByte(json, kidValueLookup, i, endKidPrefix, endKid)
	}
}

func (v *JwtVerifier) ProcessJwtPayload(
	json []uints.U8,
	issOffset, issValueLen frontend.Variable,
	audOffset, audValueLen frontend.Variable,
	subOffset, subValueLen frontend.Variable,
) (iss []uints.U8, aud []uints.U8, sub []uints.U8) {
	byteLenIssPrefix := len(ExpectedIssPrefixJson)
	endIssPrefix := v.api.Add(issOffset, byteLenIssPrefix)
	endIss := v.api.Add(endIssPrefix, issValueLen)

	byteLenAudPrefix := len(ExpectedAudPrefixJson)
	endAudPrefix := v.api.Add(audOffset, byteLenAudPrefix)
	endAud := v.api.Add(endAudPrefix, audValueLen)

	byteLenSubPrefix := len(ExpectedSubPrefixJson)
	endSubPrefix := v.api.Add(subOffset, byteLenSubPrefix)
	endSub := v.api.Add(endSubPrefix, subValueLen)

	for i := range json {
		// Check and extract the "iss" value.
		v.checkByte(json, v.issPrefixLookup, i, issOffset, endIssPrefix)
		v.checkSeparator(json, i, endIss)

		// Check and extract the "aud" value.
		v.checkByte(json, v.audPrefixLookup, i, audOffset, endAudPrefix)
		v.checkSeparator(json, i, endAud)

		// Check and extract the "sub" value.
		v.checkByte(json, v.subPrefixLookup, i, subOffset, endSubPrefix)
		v.checkSeparator(json, i, endSub)
	}

	return v.extractValues(
		json,
		endIssPrefix, issValueLen,
		endAudPrefix, audValueLen,
		endSubPrefix, subValueLen,
	)
}

func (v *JwtVerifier) checkSeparator(
	json []uints.U8,
	i int,
	end frontend.Variable,
) {
	// Get the byte from the JWT JSON.
	b := json[i].Val

	// i == end
	shouldBeSeparator := equal(v.api, i, end)

	// assert(isSeparator == 0 || (b == commaU8 || b == closeBraceU8))
	v.api.AssertIsDifferent(
		0,
		v.api.Add(
			equal(v.api, shouldBeSeparator, 0),
			v.api.Add(
				equal(v.api, b, v.commaU8.Val),
				equal(v.api, b, v.closeBraceU8.Val),
			),
		),
	)
}

func (v *JwtVerifier) checkByte(
	json []uints.U8,
	lookup *logderivlookup.Table,
	i int,
	rangeStart, rangeEnd frontend.Variable,
) {
	// Get the byte from the JWT JSON.
	b := json[i].Val

	// rangeStart <= i < rangeEnd
	shouldParse := v.api.Mul(
		not(v.api, lessThan(v.api, 16, i, rangeStart)), // i >= rangeStart
		lessThan(v.api, 16, i, rangeEnd),               // i < rangeEnd
	)

	// Get the corresponding expected byte from the lookup table.
	expectedByte := lookup.Lookup(
		v.api.Mul(
			shouldParse,
			v.api.Sub(i, rangeStart), // NOTE: It is fine to underflow here.
		),
	)[0]

	// assert(shouldParse == 0 || b == expectedByte)
	v.api.AssertIsDifferent(
		0,
		v.api.Add(
			equal(v.api, shouldParse, 0),
			equal(v.api, b, expectedByte),
		),
	)
}

func (v *JwtVerifier) extractValues(
	json []uints.U8,
	issOffset, issValueLen frontend.Variable,
	audOffset, audValueLen frontend.Variable,
	subOffset, subValueLen frontend.Variable,
) (iss []uints.U8, aud []uints.U8, sub []uints.U8) {
	// Insert all the values in the lookup table.
	valueExtractionLookup := logderivlookup.New(v.api)
	for i := range json {
		valueExtractionLookup.Insert(json[i].Val)
	}

	// Extract the "iss", "aud", and "sub" values.
	iss = make([]uints.U8, MaxJwtPayloadIssLen)
	aud = make([]uints.U8, MaxJwtPayloadAudLen)
	sub = make([]uints.U8, MaxJwtPayloadSubLen)

	v.extractValue(valueExtractionLookup, issOffset, issValueLen, iss)
	v.extractValue(valueExtractionLookup, audOffset, audValueLen, aud)
	v.extractValue(valueExtractionLookup, subOffset, subValueLen, sub)

	return iss, aud, sub
}

func (v *JwtVerifier) extractValue(
	valueExtractionLookup *logderivlookup.Table,
	offset frontend.Variable,
	length frontend.Variable,
	dst []uints.U8,
) {
	for i := range dst {
		mask := lessThan(v.api, 8, i, length)
		val := v.api.Mul(
			mask,
			valueExtractionLookup.Lookup(
				v.api.Add(
					offset,
					i,
				),
			)[0],
		)

		dst[i] = v.field.ByteValueOf(val)
	}
}
