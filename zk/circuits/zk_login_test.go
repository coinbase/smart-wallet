package circuits

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

func TestZkLogin(t *testing.T) {
	assert := test.NewAssert(t)

	jwtHeaderKidValue := `"1234567890"`
	jwtHeader := fmt.Sprintf(
		`{"typ":"JWT","alg":"RSA","kid":%s}`,
		jwtHeaderKidValue,
	)
	fmt.Printf("jwtHeader: %s\n", jwtHeader)
	// jwtHeader = "Ma"
	jwtHeaderBase64 := base64.RawURLEncoding.EncodeToString([]byte(jwtHeader))
	fmt.Printf("jwtHeaderBase64: %s\n", jwtHeaderBase64)

	jwtPayloadIssValue := `"google.com"`
	jwtPayloadAudValue := `"csw.com"`
	jwtPayloadSubValue := `"xenoliss"`
	jwtPayload := fmt.Sprintf(
		`{"iss":%s,"aud":%s,"sub":%s}`,
		jwtPayloadIssValue,
		jwtPayloadAudValue,
		jwtPayloadSubValue,
	)
	fmt.Printf("jwtPayload: %s\n", jwtPayload)
	// jwtPayload = "toto"
	jwtPayloadBase64 := base64.RawURLEncoding.EncodeToString([]byte(jwtPayload))
	fmt.Printf("jwtPayloadBase64: %s\n", jwtPayloadBase64)

	witnessJwtHeader := make([]uints.U8, MaxJwtHeaderLen)
	for i := range jwtHeader {
		witnessJwtHeader[i] = uints.NewU8(jwtHeader[i])
	}

	witnessJwtPayload := make([]uints.U8, MaxJwtPayloadLen)
	for i := range jwtPayload {
		witnessJwtPayload[i] = uints.NewU8(jwtPayload[i])
	}

	jwtBase64 := fmt.Sprintf("%s.%s", jwtHeaderBase64, jwtPayloadBase64)
	jwtHashBytes := sha256.Sum256([]byte(jwtBase64))
	jwtHash := new(big.Int).SetBytes(jwtHashBytes[1:]) // Skip the first byte (big endian) to fit the BN254 scalar field.

	assert.ProverSucceeded(
		&ZkLoginCircuit{
			// // Set public inputs values.
			// JwtHeaderKidValue: make([]uints.U8, MaxJwtHeaderKidValueLen),

			// Set private inputs sizes.
			JwtHeader:  make([]uints.U8, MaxJwtHeaderLen),
			JwtPayload: make([]uints.U8, MaxJwtPayloadLen),
		},
		&ZkLoginCircuit{
			// // Public inputs.
			// JwtHeaderKidValue: witnessJwtHeaderKidValue,
			JwtHash: jwtHash,
			// DerivedHash:       derivedHash,

			// Private inputs.
			JwtHeader:           witnessJwtHeader,
			JwtHeaderBase64Len:  len(jwtHeaderBase64),
			JwtPayload:          witnessJwtPayload,
			JwtPayloadBase64Len: len(jwtPayloadBase64),

			// TypOffset:   strings.Index(jwt, `"typ"`),
			// AlgOffset:   strings.Index(jwt, `"alg"`),
			// KidOffset:   strings.Index(jwt, `"kid"`),
			// KidValueLen: len(jwtHeaderKidValue),

			// IssOffset:   strings.Index(jwt, `"iss"`),
			// IssValueLen: len(jwtPayloadIssValue),
			// AudOffset:   strings.Index(jwt, `"aud"`),
			// AudValueLen: len(jwtPayloadAudValue),
			// SubOffset:   strings.Index(jwt, `"sub"`),
			// SubValueLen: len(jwtPayloadSubValue),
		},
		test.WithCurves(ecc.BN254),
	)
}
