package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/mdehoog/poseidon/circuits/poseidon"

	"github.com/coinbase/smart-wallet/circuits/circuits/hints"
	"github.com/coinbase/smart-wallet/circuits/circuits/jwt"
	"github.com/coinbase/smart-wallet/circuits/circuits/rsa"
	"github.com/coinbase/smart-wallet/circuits/circuits/utils"
)

const (
	ElementSize                 = 31
	MaxEphemeralPublicKeyBytes  = 64
	MaxEphemeralPublicKeyChunks = (MaxEphemeralPublicKeyBytes + ElementSize - 1) / ElementSize
)

type ZkLoginCircuit[RSAField emulated.FieldParams] struct {
	// Public inputs.
	IdpPublicKeyN      emulated.Element[RSAField] `gnark:",public"`
	EphemeralPublicKey []frontend.Variable        `gnark:",public"`
	JwtHeaderJson      []uints.U8                 `gnark:",public"`
	KidValue           []uints.U8                 `gnark:",public"`

	// Private inputs.
	JwtRandomness  frontend.Variable
	JwtPayloadJson []uints.U8
	IssValue       []uints.U8
	AudValue       []uints.U8
	SubValue       []uints.U8
	JwtSignature   emulated.Element[RSAField]
}

func (c *ZkLoginCircuit[RSAField]) Define(api frontend.API) error {
	base64Encoder := utils.NewBase64Encoder(api)

	// Compute the nonce value.
	nonceValue, err := c.computeNonceValue(api, base64Encoder)
	if err != nil {
		return err
	}

	// Instantiate the JWT verifier.
	jwtVerifier, err := jwt.NewJwtVerifier(
		api,
		base64Encoder,
		c.JwtHeaderJson,
		c.JwtPayloadJson,
		c.KidValue,
		c.IssValue,
		c.AudValue,
		c.SubValue,
		nonceValue,
	)
	if err != nil {
		return err
	}

	// Verify the JWT and compute its hash.
	jwtVerifier.VerifyJwtHeader()
	jwtVerifier.VerifyJwtPayload()
	jwtHash, err := jwtVerifier.Hash()
	if err != nil {
		return err
	}

	// Verify the JWT signature against its hash and the IDP's public key.
	err = rsa.VerifyRSASignature(api, jwtHash, &c.JwtSignature, &c.IdpPublicKeyN)
	if err != nil {
		return err
	}

	return nil
}

// computeNonceValue creates a nonce by hashing the ephemeral public key with JWT randomness
// using Poseidon, then encodes it as a base64 URL-safe string. The returned value is a 45-byte
// JSON string (with quotes) containing the 43-byte base64 representation of the hash.
// Format: "<43 base64 characters>"
func (c *ZkLoginCircuit[RSAField]) computeNonceValue(api frontend.API, base64Encoder *utils.Base64Encoder) ([]uints.U8, error) {
	inputs := make([]frontend.Variable, MaxEphemeralPublicKeyChunks+1)
	copy(inputs, c.EphemeralPublicKey)
	inputs[MaxEphemeralPublicKeyChunks] = c.JwtRandomness

	nonce := poseidon.Hash(api, inputs)
	nonceBytes, err := api.Compiler().NewHint(hints.NonceHint, 32, nonce)
	if err != nil {
		return nil, err
	}
	hints.VerifyNonce(api, nonceBytes, nonce)

	// Base64 encode the nonce.
	// NOTE: To be compatible with the base64Encoder, we must align the data to 24bits (3 bytes).
	// 	     Thus, we pad the nonce with 1 byte of zeros. This will return exactly 44 bytes but the very
	// 	     last character will be a 'A' due to the padding 0 byte. The usefull payload is only contained
	// 	     in the first 43 bytes.
	nonceBytesU8 := make([]uints.U8, 32+1)
	for i := range 32 {
		nonceBytesU8[i] = uints.U8{Val: nonceBytes[i]}
	}
	nonceBytesU8[32] = uints.U8{Val: 0}

	nonceBase64 := base64Encoder.EncodeBase64URL(nonceBytesU8)[:43]

	doubleQuoteU8 := uints.U8{Val: '"'}

	nonceValue := make([]uints.U8, 45)
	nonceValue[0] = doubleQuoteU8
	copy(nonceValue[1:], nonceBase64)
	nonceValue[44] = doubleQuoteU8

	return nonceValue, nil
}
