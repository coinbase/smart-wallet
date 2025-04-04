package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

type JwtVerifier struct {
	api frontend.API

	commaU8      uints.U8
	closeBraceU8 uints.U8

	// Payload lookup tables.
	issPrefixLookup   *logderivlookup.Table
	audPrefixLookup   *logderivlookup.Table
	subPrefixLookup   *logderivlookup.Table
	noncePrefixLookup *logderivlookup.Table
}

func NewJwtVerifier(api frontend.API) *JwtVerifier {
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

	noncePrefixLookup := logderivlookup.New(api)
	for _, v := range ExpectedNoncePrefixJson {
		noncePrefixLookup.Insert(v)
	}

	return &JwtVerifier{
		api: api,

		commaU8:      uints.NewU8(','),
		closeBraceU8: uints.NewU8('}'),

		// Payload lookup tables.
		issPrefixLookup:   issPrefixLookup,
		audPrefixLookup:   audPrefixLookup,
		subPrefixLookup:   subPrefixLookup,
		noncePrefixLookup: noncePrefixLookup,
	}
}

func (v *JwtVerifier) ProcessJwtPayload(
	json []uints.U8,
	expectedNonce []uints.U8,
	issOffset, issLen frontend.Variable,
	audOffset, audLen frontend.Variable,
	subOffset, subLen frontend.Variable,
	nonceOffset, nonceLen frontend.Variable,
) (iss []uints.U8, aud []uints.U8, sub []uints.U8) {

	byteLenIssPrefix := len(ExpectedIssPrefixJson)
	endIssPrefix := v.api.Add(issOffset, byteLenIssPrefix)
	endIss := v.api.Add(endIssPrefix, issLen)

	byteLenAudPrefix := len(ExpectedAudPrefixJson)
	endAudPrefix := v.api.Add(audOffset, byteLenAudPrefix)
	endAud := v.api.Add(endAudPrefix, audLen)

	byteLenSubPrefix := len(ExpectedSubPrefixJson)
	endSubPrefix := v.api.Add(subOffset, byteLenSubPrefix)
	endSub := v.api.Add(endSubPrefix, subLen)

	byteLenNoncePrefix := len(ExpectedNoncePrefixJson)
	endNoncePrefix := v.api.Add(nonceOffset, byteLenNoncePrefix)
	endNonce := v.api.Add(endNoncePrefix, nonceLen)

	nonceValueLookup := logderivlookup.New(v.api)
	for _, v := range expectedNonce {
		nonceValueLookup.Insert(v.Val)
	}

	for i := range json {
		// Check the "iss" prefix and separator.
		v.checkByte(json, v.issPrefixLookup, i, issOffset, endIssPrefix)
		v.checkSeparator(json, i, endIss)

		// Check the "aud" prefix and separator.
		v.checkByte(json, v.audPrefixLookup, i, audOffset, endAudPrefix)
		v.checkSeparator(json, i, endAud)

		// Check the "sub" prefix and separator.
		v.checkByte(json, v.subPrefixLookup, i, subOffset, endSubPrefix)
		v.checkSeparator(json, i, endSub)

		// Check the "nonce" prefix, value and separator.
		v.checkByte(json, v.noncePrefixLookup, i, nonceOffset, endNoncePrefix)
		v.checkByte(json, nonceValueLookup, i, endNoncePrefix, endNonce)
		v.checkSeparator(json, i, endNonce)
	}

	return v.extractValues(
		json,
		endIssPrefix, issLen,
		endAudPrefix, audLen,
		endSubPrefix, subLen,
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
		not(v.api, lessThan(v.api, 11, i, rangeStart)), // i >= rangeStart
		lessThan(v.api, 11, i, rangeEnd),               // i < rangeEnd
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
	issOffset, issLen frontend.Variable,
	audOffset, audLen frontend.Variable,
	subOffset, subLen frontend.Variable,
) (iss []uints.U8, aud []uints.U8, sub []uints.U8) {
	// Insert all the values in the lookup table.
	valueExtractionLookup := logderivlookup.New(v.api)
	for i := range json {
		valueExtractionLookup.Insert(json[i].Val)
	}

	// Extract the "iss", "aud", and "sub" values.
	iss = make([]uints.U8, MaxIssLen)
	aud = make([]uints.U8, MaxAudLen)
	sub = make([]uints.U8, MaxSubLen)

	v.extractValue(valueExtractionLookup, issOffset, issLen, iss)
	v.extractValue(valueExtractionLookup, audOffset, audLen, aud)
	v.extractValue(valueExtractionLookup, subOffset, subLen, sub)

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

		dst[i] = uints.U8{Val: val}
	}
}
