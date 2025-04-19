package jwt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/coinbase/smart-wallet/circuits/circuits/utils"
)

var (
	commaU8      = uints.NewU8(',')
	closeBraceU8 = uints.NewU8('}')
)

// Wrapper struct that contains all the information needed to verify a JWT.
type jwtVerifier struct {
	api frontend.API

	base64Encoder *utils.Base64Encoder

	headerJson, payloadJson []uints.U8

	// Header lookup tables.
	typLookup *logderivlookup.Table
	algLookup *logderivlookup.Table
	kidLookup *logderivlookup.Table

	// Payload lookup tables.
	issLookup   *logderivlookup.Table
	audLookup   *logderivlookup.Table
	subLookup   *logderivlookup.Table
	nonceLookup *logderivlookup.Table

	// Base64 info.
	headerBase64Len, payloadBase64Len            frontend.Variable
	headerBase64Mask, dotMask, payloadBase64Mask []frontend.Variable

	// Header info.
	typOffset, algOffset, kidOffset, kidValueLen frontend.Variable
	typMask, algMask, kidMask                    []frontend.Variable

	// Payload info.
	issOffset, issValueLen               frontend.Variable
	audOffset, audValueLen               frontend.Variable
	subOffset, subValueLen               frontend.Variable
	nonceOffset, nonceValueLen           frontend.Variable // NOTE: The nonceValueLen could be hardcoded to 45 bytes (43 base64 encoded bytes + 2 quotes)
	issMask, audMask, subMask, nonceMask []frontend.Variable
}

// NewJwtVerifier creates a new JWT verifier.
func NewJwtVerifier(
	api frontend.API,
	base64Encoder *utils.Base64Encoder,
	headerJson []uints.U8,
	payloadJson []uints.U8,
	kidValue []uints.U8,
	issValue []uints.U8,
	audValue []uints.U8,
	subValue []uints.U8,
	nonceValue []uints.U8,
) (*jwtVerifier, error) {
	typLookup := buildLookup(api, TypJson, nil)
	algLookup := buildLookup(api, AlgJson, nil)
	kidLookup := buildLookup(api, KidJsonPrefix, kidValue)

	issLookup := buildLookup(api, IssJsonPrefix, issValue)
	audLookup := buildLookup(api, AudJsonPrefix, audValue)
	subLookup := buildLookup(api, SubJsonPrefix, subValue)
	nonceLookup := buildLookup(api, NonceJsonPrefix, nonceValue)

	typOffset, algOffset, kidOffset, err := headerOffsetsFromHints(api, headerJson)
	if err != nil {
		return nil, err
	}

	kidValueLen, err := headerValueLengthsFromHints(api, headerJson)
	if err != nil {
		return nil, err
	}

	issOffset, audOffset, subOffset, nonceOffset, err := payloadOffsetsFromHints(api, payloadJson)
	if err != nil {
		return nil, err
	}

	issValueLen, audValueLen, subValueLen, nonceValueLen, err := payloadValueLengthsFromHints(api, payloadJson)
	if err != nil {
		return nil, err
	}

	headerBase64Len, payloadBase64Len, err := sectionBase64LenghtsFromHints(api, headerJson, payloadJson)
	if err != nil {
		return nil, err
	}

	headerBase64Mask, dotMask, payloadBase64Mask, err := sectionBase64MasksFromHints(api, headerBase64Len, payloadBase64Len)
	if err != nil {
		return nil, err
	}

	typMask, algMask, kidMask, err := headerMasksFromHints(api, typOffset, algOffset, kidOffset, kidValueLen)
	if err != nil {
		return nil, err
	}

	issMask, audMask, subMask, nonceMask, err := payloadMasksFromHints(
		api,
		issOffset,
		issValueLen,
		audOffset,
		audValueLen,
		subOffset,
		subValueLen,
		nonceOffset,
		nonceValueLen,
	)

	if err != nil {
		return nil, err
	}

	jwtVerifier := &jwtVerifier{
		api: api,

		base64Encoder: base64Encoder,

		headerJson:  headerJson,
		payloadJson: payloadJson,

		// Header lookup tables.
		typLookup:   typLookup,
		algLookup:   algLookup,
		kidLookup:   kidLookup,
		kidValueLen: kidValueLen,

		// Payload lookup tables.
		issLookup:   issLookup,
		audLookup:   audLookup,
		subLookup:   subLookup,
		nonceLookup: nonceLookup,

		// Base64 info.
		headerBase64Len:   headerBase64Len,
		payloadBase64Len:  payloadBase64Len,
		headerBase64Mask:  headerBase64Mask,
		dotMask:           dotMask,
		payloadBase64Mask: payloadBase64Mask,

		// Header info.
		typOffset: typOffset,
		algOffset: algOffset,
		kidOffset: kidOffset,
		typMask:   typMask,
		algMask:   algMask,
		kidMask:   kidMask,

		// Payload info.
		issOffset:     issOffset,
		issValueLen:   issValueLen,
		audOffset:     audOffset,
		audValueLen:   audValueLen,
		subOffset:     subOffset,
		subValueLen:   subValueLen,
		nonceOffset:   nonceOffset,
		nonceValueLen: nonceValueLen,
		issMask:       issMask,
		audMask:       audMask,
		subMask:       subMask,
		nonceMask:     nonceMask,
	}

	return jwtVerifier, nil
}

// VerifyJwtHeader verifies the JWT header.
// It performs the following checks:
// - Verifies the "typ" field is present and has the value "JWT"
// - Verifies the "alg" field is present and has the value "RS256"
// - Verifies the "kid" field is present and matches the expected kidValue.
// - Ensures each field is properly separated by commas or closing braces.
func (v *jwtVerifier) VerifyJwtHeader() {
	endTypOffset := v.api.Add(v.typOffset, len(TypJson))
	endAlgOffset := v.api.Add(v.algOffset, len(AlgJson))
	endKidOffset := v.api.Add(v.kidOffset, len(KidJsonPrefix), v.kidValueLen)

	for i := range v.headerJson {
		// Check the "typ" prefix, value and separator.
		verifyByte(v.api, v.headerJson, v.typLookup, i, v.typMask[i], v.typOffset)
		verifySeparator(v.api, v.headerJson, i, endTypOffset)

		// Check the "alg" prefix, value and separator.
		verifyByte(v.api, v.headerJson, v.algLookup, i, v.algMask[i], v.algOffset)
		verifySeparator(v.api, v.headerJson, i, endAlgOffset)

		// Check the "kid" prefix and separator.
		verifyByte(v.api, v.headerJson, v.kidLookup, i, v.kidMask[i], v.kidOffset)
		verifySeparator(v.api, v.headerJson, i, endKidOffset)
	}
}

// VerifyJwtPayload verifies the JWT payload.
// It performs the following checks:
// - Verifies the "iss" field is present and matches the expected issValue.
// - Verifies the "aud" field is present and matches the expected audValue.
// - Verifies the "sub" field is present and matches the expected subValue.
// - Verifies the "nonce" field is present and matches the expected nonceValue.
// - Ensures each field is properly separated by commas or closing braces.
func (v *jwtVerifier) VerifyJwtPayload() {
	endIssOffset := v.api.Add(v.issOffset, len(IssJsonPrefix), v.issValueLen)
	endAudOffset := v.api.Add(v.audOffset, len(AudJsonPrefix), v.audValueLen)
	endSubOffset := v.api.Add(v.subOffset, len(SubJsonPrefix), v.subValueLen)
	endNonceOffset := v.api.Add(v.nonceOffset, len(NonceJsonPrefix), v.nonceValueLen)

	for i := range v.payloadJson {
		// Check the "iss" prefix, value and separator.
		verifyByte(v.api, v.payloadJson, v.issLookup, i, v.issMask[i], v.issOffset)
		verifySeparator(v.api, v.payloadJson, i, endIssOffset)

		// Check the "aud" prefix, value and separator.
		verifyByte(v.api, v.payloadJson, v.audLookup, i, v.audMask[i], v.audOffset)
		verifySeparator(v.api, v.payloadJson, i, endAudOffset)

		// Check the "sub" prefix, value and separator.
		verifyByte(v.api, v.payloadJson, v.subLookup, i, v.subMask[i], v.subOffset)
		verifySeparator(v.api, v.payloadJson, i, endSubOffset)

		// Check the "nonce" prefix, value and separator.
		verifyByte(v.api, v.payloadJson, v.nonceLookup, i, v.nonceMask[i], v.nonceOffset)
		verifySeparator(v.api, v.payloadJson, i, endNonceOffset)
	}
}

// Hash computes the SHA-256 hash of the base64-encoded JWT header and payload.
// Returns the hash as a slice of (32) frontend.Variable.
func (v *jwtVerifier) Hash() ([]frontend.Variable, error) {
	jwtPackedBase64 := v.packBase64()

	sha, err := sha2.New(v.api)
	if err != nil {
		return nil, err
	}
	sha.Write(jwtPackedBase64)
	hashBytes := sha.FixedLengthSum(v.api.Add(v.headerBase64Len, frontend.Variable(1), v.payloadBase64Len))
	hash := make([]frontend.Variable, 0, len(hashBytes))
	for i := range hashBytes {
		hash = append(hash, hashBytes[i].Val)
	}

	return hash, nil
}

// packBase64 encodes the JWT header and payload as base64URL, concatenates them with a dot separator (header.payload),
// and returns the packed base64 as a slice of uints.U8. This packed representation is only used in the Hash method.
func (v *jwtVerifier) packBase64() (packedBase64 []uints.U8) {
	headerBase64 := v.base64Encoder.EncodeBase64URL(v.headerJson)
	payloadBase64 := v.base64Encoder.EncodeBase64URL(v.payloadJson)

	// Lookup table (size = MaxPayloadLenBase64): <payload> + <padding>
	payloadBase64Lookup := logderivlookup.New(v.api)
	for _, b := range payloadBase64 {
		payloadBase64Lookup.Insert(b.Val)
	}

	packedBase64 = make([]uints.U8, MaxLenBase64)
	for i := range packedBase64 {
		packedBase64[i] = uints.NewU8(0)
	}

	startPayloadIndex := v.api.Add(v.headerBase64Len, 1)

	copy(packedBase64, headerBase64)
	for i := range MaxLenBase64 {
		isHeader := v.headerBase64Mask[i]
		isDot := v.dotMask[i]
		isPayload := v.payloadBase64Mask[i]

		payloadByte := payloadBase64Lookup.Lookup(
			v.api.Mul(isPayload, v.api.Sub(i, startPayloadIndex)),
		)[0]

		b := v.api.Add(
			v.api.Mul(isHeader, packedBase64[i].Val),
			v.api.Mul(isDot, '.'),
			v.api.Mul(isPayload, payloadByte),
		)
		packedBase64[i] = uints.U8{Val: b}
	}

	return

}
