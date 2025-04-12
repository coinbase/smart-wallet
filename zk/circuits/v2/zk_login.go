package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mdehoog/poseidon/circuits/poseidon"

	"github.com/coinbase/smart-wallet/circuits/circuits/v2/hints"
	"github.com/coinbase/smart-wallet/circuits/circuits/v2/jwt"
)

const (
	ElementSize        = 31
	MaxPublicKeyBytes  = 64
	MaxPublicKeyChunks = (MaxPublicKeyBytes + ElementSize - 1) / ElementSize
)

type ZkLoginCircuitV2 struct {
	// Public inputs.
	PublicKey     []frontend.Variable `gnark:",public"`
	JwtHeaderJson []uints.U8          `gnark:",public"`
	KidValue      []uints.U8          `gnark:",public"`

	// Private inputs.
	JwtRandomness  frontend.Variable
	JwtPayloadJson []uints.U8
	IssValue       []uints.U8
	AudValue       []uints.U8
	SubValue       []uints.U8
}

func (c *ZkLoginCircuitV2) Define(api frontend.API) error {
	_, err := c.computeNonce(api)
	if err != nil {
		return err
	}

	jwtVerifier, err := jwt.NewJwtVerifier(
		api,

		c.JwtHeaderJson,
		c.JwtPayloadJson,

		c.KidValue,

		c.IssValue,
		c.AudValue,
		c.SubValue,
	)

	if err != nil {
		return err
	}

	jwtVerifier.ProcessJwtHeader()
	jwtVerifier.ProcessJwtPayload()
	jwtVerifier.Pack()

	return nil
}

func (c *ZkLoginCircuitV2) computeNonce(api frontend.API) (frontend.Variable, error) {
	inputs := make([]frontend.Variable, MaxPublicKeyChunks+1)
	copy(inputs, c.PublicKey)
	inputs[MaxPublicKeyChunks] = c.JwtRandomness

	nonce := poseidon.Hash(api, inputs)
	nonceBytes, err := api.Compiler().NewHint(hints.NonceHint, 32, nonce)
	if err != nil {
		return 0, err
	}

	hints.VerifyNonce(api, nonceBytes, nonce)

	return nonce, nil
}
