package circuits

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

func TestZkLogin(t *testing.T) {
	assert := test.NewAssert(t)

	// declare the circuit
	cubicCircuit := ZkLoginCircuit{
		JwtBase64: make([]uints.U8, MaxJwtBase64Len),
	}

	jwt := `{"typ":"JWT","alg":"ES256","crv":"P-256","kid":"1234567890"}`
	jwtBytes := []uint8(jwt)
	jwtBase64 := []uint8(base64.URLEncoding.EncodeToString(jwtBytes))

	witnessJwtBase64 := make([]uints.U8, MaxJwtBase64Len)
	for i := range jwtBase64 {
		witnessJwtBase64[i] = uints.NewU8(jwtBase64[i])
	}

	assert.ProverSucceeded(&cubicCircuit, &ZkLoginCircuit{
		JwtBase64:    witnessJwtBase64,
		JwtBase64Len: len(jwtBase64),

		TypOffset: strings.Index(jwt, "typ") - 1,
		AlgOffset: strings.Index(jwt, "alg") - 1,
		CrvOffset: strings.Index(jwt, "crv") - 1,

		KidOffset:   strings.Index(jwt, "kid") - 1,
		KidValueLen: len(`"1234567890"`),
	}, test.WithCurves(ecc.BN254))
}
