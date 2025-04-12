package jwt

import (
	"github.com/coinbase/smart-wallet/circuits/circuits/v2/utils"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

var (
	commaU8      = uints.NewU8(',')
	closeBraceU8 = uints.NewU8('}')
)

type JwtVerifier struct {
	api frontend.API

	headerJson  []uints.U8
	payloadJson []uints.U8

	// Header lookup tables.
	typLookup *logderivlookup.Table
	algLookup *logderivlookup.Table
	kidLookup *logderivlookup.Table

	// Payload lookup tables.
	issLookup *logderivlookup.Table
	audLookup *logderivlookup.Table
	subLookup *logderivlookup.Table

	// Header info.
	typOffset, algOffset, kidOffset, kidValueLen frontend.Variable
	typMask, algMask, kidMask                    []frontend.Variable

	// Payload info.
	issOffset, issValueLen, audOffset, audValueLen, subOffset, subValueLen frontend.Variable
	issMask, audMask, subMask                                              []frontend.Variable
}

func NewJwtVerifier(
	api frontend.API,

	headerJson []uints.U8,
	payloadJson []uints.U8,

	expectedKid []uints.U8,

	issValue []uints.U8,
	audValue []uints.U8,
	subValue []uints.U8,
) (*JwtVerifier, error) {
	typLookup := buildLookup(api, TypJson, nil)
	algLookup := buildLookup(api, AlgJson, nil)
	kidLookup := buildLookup(api, KidJsonPrefix, expectedKid)

	issLookup := buildLookup(api, IssJsonPrefix, issValue)
	audLookup := buildLookup(api, AudJsonPrefix, audValue)
	subLookup := buildLookup(api, SubJsonPrefix, subValue)

	typOffset, algOffset, kidOffset, err := jwtHeaderOffsetsFromHints(api, headerJson)
	if err != nil {
		return nil, err
	}

	kidValueLen, err := jwtHeaderValueLengthsFromHints(api, headerJson)
	if err != nil {
		return nil, err
	}

	issOffset, audOffset, subOffset, err := jwtPayloadOffsetsFromHints(api, payloadJson)
	if err != nil {
		return nil, err
	}

	issValueLen, audValueLen, subValueLen, err := jwtPayloadValueLengthsFromHints(api, payloadJson)
	if err != nil {
		return nil, err
	}

	typMask, algMask, kidMask, err := jwtHeaderMasksFromHints(api, typOffset, algOffset, kidOffset, kidValueLen)
	if err != nil {
		return nil, err
	}

	issMask, audMask, subMask, err := jwtPayloadMasksFromHints(api, issOffset, issValueLen, audOffset, audValueLen, subOffset, subValueLen)
	if err != nil {
		return nil, err
	}

	jwtVerifier := &JwtVerifier{
		api: api,

		headerJson:  headerJson,
		payloadJson: payloadJson,

		// Header lookup tables.
		typLookup:   typLookup,
		algLookup:   algLookup,
		kidLookup:   kidLookup,
		kidValueLen: kidValueLen,

		// Payload lookup tables.
		issLookup: issLookup,
		audLookup: audLookup,
		subLookup: subLookup,

		// Header info.
		typOffset: typOffset,
		algOffset: algOffset,
		kidOffset: kidOffset,
		typMask:   typMask,
		algMask:   algMask,
		kidMask:   kidMask,

		// Payload info.
		issOffset:   issOffset,
		issValueLen: issValueLen,
		audOffset:   audOffset,
		audValueLen: audValueLen,
		subOffset:   subOffset,
		subValueLen: subValueLen,
		issMask:     issMask,
		audMask:     audMask,
		subMask:     subMask,
	}

	return jwtVerifier, nil
}

func (v *JwtVerifier) ProcessJwtHeader() {
	endTypOffset := v.api.Add(v.typOffset, len(TypJson))
	endAlgOffset := v.api.Add(v.algOffset, len(AlgJson))
	endKidOffset := v.api.Add(v.kidOffset, len(KidJsonPrefix), v.kidValueLen)

	for i := range v.headerJson {
		// Check the "typ" prefix, value and separator.
		checkByte(v.api, v.headerJson, v.typLookup, i, v.typMask[i], v.typOffset)
		checkSeparator(v.api, v.headerJson, i, endTypOffset)

		// Check the "alg" prefix, value and separator.
		checkByte(v.api, v.headerJson, v.algLookup, i, v.algMask[i], v.algOffset)
		checkSeparator(v.api, v.headerJson, i, endAlgOffset)

		// Check the "kid" prefix and separator.
		checkByte(v.api, v.headerJson, v.kidLookup, i, v.kidMask[i], v.kidOffset)
		checkSeparator(v.api, v.headerJson, i, endKidOffset)
	}
}

func (v *JwtVerifier) ProcessJwtPayload() {
	endIssOffset := v.api.Add(v.issOffset, len(IssJsonPrefix), v.issValueLen)
	endAudOffset := v.api.Add(v.audOffset, len(AudJsonPrefix), v.audValueLen)
	endSubOffset := v.api.Add(v.subOffset, len(SubJsonPrefix), v.subValueLen)

	for i := range v.payloadJson {
		// Check the "iss" prefix, value and separator.
		checkByte(v.api, v.payloadJson, v.issLookup, i, v.issMask[i], v.issOffset)
		checkSeparator(v.api, v.payloadJson, i, endIssOffset)

		// Check the "aud" prefix, value and separator.
		checkByte(v.api, v.payloadJson, v.audLookup, i, v.audMask[i], v.audOffset)
		checkSeparator(v.api, v.payloadJson, i, endAudOffset)

		// Check the "sub" prefix, value and separator.
		checkByte(v.api, v.payloadJson, v.subLookup, i, v.subMask[i], v.subOffset)
		checkSeparator(v.api, v.payloadJson, i, endSubOffset)
	}
}

func (v *JwtVerifier) Pack() []frontend.Variable {
	base64Encoder := utils.NewBase64Encoder(v.api)
	headerBase64 := base64Encoder.EncodeBase64URL(v.headerJson)
	// payloadBase64 := base64Encoder.EncodeBase64URL(v.payloadJson)

	packedJwt := make([]frontend.Variable, MaxLenBase64)
	for i := range packedJwt {
		packedJwt[i] = uints.NewU8(0)
	}
	copy(packedJwt, headerBase64)

	return packedJwt

}
