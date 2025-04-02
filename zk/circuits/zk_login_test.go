package circuits

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

func TestZkLogin(t *testing.T) {
	assert := test.NewAssert(t)

	// {"typ":"JWT","alg":"RS256","kid":"1234567890"}
	jwtHeaderKidValue := `"1234567890"`
	jwtHeader := fmt.Sprintf(
		`{"typ":"JWT","alg":"RS256","kid":%s}`,
		jwtHeaderKidValue,
	)
	jwtHeaderBase64 := base64.RawURLEncoding.EncodeToString([]byte(jwtHeader))

	// {"iss":"google.com","aud":"csw.com","sub":"xenoliss"}
	jwtPayloadIssValue := `"google.com"`
	jwtPayloadAudValue := `"csw.com"`
	jwtPayloadSubValue := `"xenoliss"`
	jwtPayload := fmt.Sprintf(
		`{"iss":%s,"aud":%s,"sub":%s}`,
		jwtPayloadIssValue,
		jwtPayloadAudValue,
		jwtPayloadSubValue,
	)
	jwtPayloadBase64 := base64.RawURLEncoding.EncodeToString([]byte(jwtPayload))

	witnessJwtHeader := make([]uints.U8, MaxJwtHeaderLen)
	for i := range jwtHeader {
		witnessJwtHeader[i] = uints.NewU8(jwtHeader[i])
	}

	witnessJwtHeaderKidValue := make([]uints.U8, MaxJwtHeaderKidValueLen)
	for i := range jwtHeaderKidValue {
		witnessJwtHeaderKidValue[i] = uints.NewU8(jwtHeaderKidValue[i])
	}

	witnessJwtPayload := make([]uints.U8, MaxJwtPayloadLen)
	for i := range jwtPayload {
		witnessJwtPayload[i] = uints.NewU8(jwtPayload[i])
	}

	bytes := make([]uint8, MaxJwtPayloadIssLen+MaxJwtPayloadAudLen+MaxJwtPayloadSubLen)
	copy(bytes, jwtPayloadIssValue)
	copy(bytes[MaxJwtPayloadIssLen:], jwtPayloadAudValue)
	copy(bytes[MaxJwtPayloadIssLen+MaxJwtPayloadAudLen:], jwtPayloadSubValue)
	derivedHashBytes := sha256.Sum256(bytes)
	derivedHash := new(big.Int).SetBytes(derivedHashBytes[1:]) // Skip the first byte (big endian) to fit the BN254 scalar field.

	jwtBase64 := fmt.Sprintf("%s.%s", jwtHeaderBase64, jwtPayloadBase64)
	jwtHashBytes := sha256.Sum256([]byte(jwtBase64))
	jwtHash := new(big.Int).SetBytes(jwtHashBytes[1:]) // Skip the first byte (big endian) to fit the BN254 scalar field.

	assert.ProverSucceeded(
		&ZkLoginCircuit{
			// Set public inputs values.
			JwtHeaderKidValue: make([]uints.U8, MaxJwtHeaderKidValueLen),

			// Set private inputs sizes.
			JwtHeader:  make([]uints.U8, MaxJwtHeaderLen),
			JwtPayload: make([]uints.U8, MaxJwtPayloadLen),
		},
		&ZkLoginCircuit{
			// Public inputs.
			JwtHeaderKidValue: witnessJwtHeaderKidValue,
			JwtHash:           jwtHash,
			DerivedHash:       derivedHash,

			// Private inputs.
			JwtHeader:           witnessJwtHeader,
			JwtHeaderBase64Len:  len(jwtHeaderBase64),
			JwtPayload:          witnessJwtPayload,
			JwtPayloadBase64Len: len(jwtPayloadBase64),

			TypOffset:   strings.Index(jwtHeader, `"typ"`),
			AlgOffset:   strings.Index(jwtHeader, `"alg"`),
			KidOffset:   strings.Index(jwtHeader, `"kid"`),
			KidValueLen: len(jwtHeaderKidValue),

			IssOffset:   strings.Index(jwtPayload, `"iss"`),
			IssValueLen: len(jwtPayloadIssValue),
			AudOffset:   strings.Index(jwtPayload, `"aud"`),
			AudValueLen: len(jwtPayloadAudValue),
			SubOffset:   strings.Index(jwtPayload, `"sub"`),
			SubValueLen: len(jwtPayloadSubValue),
		},
		test.WithCurves(ecc.BN254),
	)
}
