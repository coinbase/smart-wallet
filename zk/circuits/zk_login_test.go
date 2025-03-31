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

	jwtHeaderKidValue := `"1234567890"`
	jwtHeader := fmt.Sprintf(
		`{"typ":"JWT","alg":"RSA","kid":%s}`,
		jwtHeaderKidValue,
	)

	//{"iss":"xenoliss","aud":"google.com","sub":"csw.com"}
	jwtPayloadIssValue := `"google.com"`
	jwtPayloadAudValue := `"csw.com"`
	jwtPayloadSubValue := `"xenoliss"`
	jwtPayload := fmt.Sprintf(
		`{"iss":%s,"aud":%s,"sub":%s}`,
		jwtPayloadIssValue,
		jwtPayloadAudValue,
		jwtPayloadSubValue,
	)

	jwt := fmt.Sprintf("%s.%s", jwtHeader, jwtPayload)

	witnessJwtHeaderKidValue := make([]uints.U8, MaxJwtHeaderKidValueLen)
	for i := range jwtHeaderKidValue {
		witnessJwtHeaderKidValue[i] = uints.NewU8(jwtHeaderKidValue[i])
	}

	buf := make([]uint8, MaxJwtPayloadIssLen+MaxJwtPayloadAudLen+MaxJwtPayloadSubLen)
	copy(buf[:], jwtPayloadIssValue)
	copy(buf[MaxJwtPayloadIssLen:], jwtPayloadAudValue)
	copy(buf[MaxJwtPayloadIssLen+MaxJwtPayloadAudLen:], jwtPayloadSubValue)
	hashBytes := sha256.Sum256(buf)
	derivedHash := new(big.Int).SetBytes(hashBytes[1:]) // Skip the first byte (big endian) to fit the BN254 scalar field.

	jwtHeaderBase64 := base64.URLEncoding.EncodeToString([]byte(jwtHeader))
	jwtPayloadBase64 := base64.URLEncoding.EncodeToString([]byte(jwtPayload))
	jwtBase64 := fmt.Sprintf("%s.%s", jwtHeaderBase64, jwtPayloadBase64)

	witnessJwtBase64 := make([]uints.U8, MaxJwtLen)
	for i := range jwtBase64 {
		witnessJwtBase64[i] = uints.NewU8(jwtBase64[i])
	}
	jwtHashBytes := sha256.Sum256([]byte(jwtBase64))
	jwtHash := new(big.Int).SetBytes(jwtHashBytes[1:]) // Skip the first byte (big endian) to fit the BN254 scalar field.

	assert.ProverSucceeded(
		&ZkLoginCircuit{
			// Set public inputs values.
			JwtHeaderKidValue: make([]uints.U8, MaxJwtHeaderKidValueLen),

			// Set private inputs sizes.
			JwtBase64: make([]uints.U8, MaxJwtLen),
		},
		&ZkLoginCircuit{
			// Public inputs.
			JwtHeaderKidValue: witnessJwtHeaderKidValue,
			JwtHash:           jwtHash,
			DerivedHash:       derivedHash,

			// Private inputs.
			JwtBase64:    witnessJwtBase64,
			JwtBase64Len: len(jwtBase64),

			TypOffset:   strings.Index(jwt, `"typ"`),
			AlgOffset:   strings.Index(jwt, `"alg"`),
			KidOffset:   strings.Index(jwt, `"kid"`),
			KidValueLen: len(jwtHeaderKidValue),

			IssOffset:   strings.Index(jwt, `"iss"`),
			IssValueLen: len(jwtPayloadIssValue),
			AudOffset:   strings.Index(jwt, `"aud"`),
			AudValueLen: len(jwtPayloadAudValue),
			SubOffset:   strings.Index(jwt, `"sub"`),
			SubValueLen: len(jwtPayloadSubValue),
		},
		test.WithCurves(ecc.BN254),
	)
}
