package circuits_test

import (
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/coinbase/smart-wallet/circuits/circuits"
	"github.com/coinbase/smart-wallet/circuits/circuits/hints"
	"github.com/coinbase/smart-wallet/circuits/circuits/jwt"
	"github.com/coinbase/smart-wallet/circuits/circuits/rsa"
	"github.com/coinbase/smart-wallet/circuits/utils"
)

func TestZkLoginV2(t *testing.T) {
	assert := test.NewAssert(t)

	_, _, ephAddress := generateKeypair()
	ephPubKey := ephAddress.Bytes()
	idpPubKeyNBase64 := "vUiHFY8O45dBoYLGipsgaVOk7rGpim6CK1iPG2zSt3sO9-09S9dB5nQdIelGye-mouQXaW5U7H8lZnv5wLJ8VSzquaSh3zJkbDq-Wvgas6U-FJaMy35kiExr5gUKUGPAIjI2sLASDbFD0vT_jxtg0ZRknwkexz_gZadZQ-iFEO7unjpE_zQnx8LhN-3a8dRf2B45BLY5J9aQJi4Csa_NHzl9Ym4uStYraSgwW93VYJwDJ3wKTvwejPvlW3n0hUifvkMke3RTqnSDIbP2xjtNmj12wdd-VUw47-cor5lMn7LG400G7lmI8rUSEHIzC7UyzEW7y15_uzuqvIkFVTLXlQ"
	jwtHeaderJson := `{"alg":"RS256","kid":"c37da75c9fbe18c2ce9125b9aa1f300dcb31e8d9","typ":"JWT"}`
	jwtPayloadJson := `{"iss":"https://accounts.google.com","azp":"875735819865-ictb0rltgphgvhrgm125n5ch366tq8pv.apps.googleusercontent.com","aud":"875735819865-ictb0rltgphgvhrgm125n5ch366tq8pv.apps.googleusercontent.com","sub":"113282815992720230663","at_hash":"jV2oDvBCBKV1y_7_8roqTA","nonce":"LTtll2v68lOJtOU04536biInGt7NpYkkGeIklY6SNdU","iat":1745087371,"exp":1745090971}`
	jwtSignatureBase64 := "nfSMXjM5v5UR8SrqrKCMxIQ6_Jw_K35rpqwAlQVrw_2xstGzUD0YIeJlXXDRD6zVVcVXh0YkHa4GfzfKYhSdqlOawWXpGIjyEfurcI0KlDTY50xxU5GP239-09ZAJDlzKG-r5mmRNThN6Ue9wnhN-sRyio2AVCtTuJVbU9RrM8NnstKwtxe-0Ak0aifu7ZsNHORbbgK6_eNnd30RLCNdOQn0pf_g9d9gQjVcI35z8h3c8-1rvLJRp02epIG-ewQHcjUCRDXZ9LOFEswmVg8ulILx_KyLmhIdlYgmbPI3j8OaMPN1MNwXTF-VuCcOCOnj6z8rS-bwZ5UZBDDSlpqJIw"
	jwtRandomness := new(big.Int).SetUint64(42)
	userSalt := new(big.Int).SetUint64(4242)

	witnessPublicHash, witnessIdpPubKeyN, witnessEphPubKey, witnessJwtHeaderJson, witnessKidValue, witnessZkAddr, witnessJwtPayloadJson, witnessIssValue, witnessAudValue, witnessSubValue, witnessJwtSignature, witnessJwtRandomness, witnessUserSalt, err := utils.GenerateWitness[rsa.Mod1e2048](
		ephPubKey,
		idpPubKeyNBase64,
		jwtHeaderJson,
		jwtPayloadJson,
		jwtSignatureBase64,
		jwtRandomness,
		userSalt,
	)
	if err != nil {
		t.Fatalf("failed to generate witness: %v", err)
	}

	assert.ProverSucceeded(
		&circuits.ZkLoginCircuit[rsa.Mod1e2048]{
			// Semi-public inputs sizes.
			KidValue: make([]uints.U8, jwt.MaxKidValueLen),

			// Private non-sensitive inputs sizes.
			JwtHeaderJson: make([]uints.U8, jwt.MaxHeaderJsonLen),

			// Private sensitive inputs sizes.
			JwtPayloadJson: make([]uints.U8, jwt.MaxPayloadJsonLen),
			IssValue:       make([]uints.U8, jwt.MaxIssValueLen),
			AudValue:       make([]uints.U8, jwt.MaxAudValueLen),
			SubValue:       make([]uints.U8, jwt.MaxSubValueLen),
		},
		&circuits.ZkLoginCircuit[rsa.Mod1e2048]{
			// Public inputs.
			PublicHash: witnessPublicHash,

			// Semi-public inputs.
			IdpPubKeyN: witnessIdpPubKeyN,
			EphPubKey:  witnessEphPubKey,
			KidValue:   witnessKidValue,
			ZkAddr:     witnessZkAddr,

			// Private non-sensitive inputs.
			JwtHeaderJson: witnessJwtHeaderJson,

			// Private inputs.
			JwtPayloadJson: witnessJwtPayloadJson,
			IssValue:       witnessIssValue,
			AudValue:       witnessAudValue,
			SubValue:       witnessSubValue,
			JwtSignature:   witnessJwtSignature,
			JwtRandomness:  witnessJwtRandomness,
			UserSalt:       witnessUserSalt,
		},
		test.WithCurves(ecc.BN254),
		test.WithSolverOpts(solver.WithHints(
			hints.OffsetHint,
			hints.JsonValueLenHint,
			hints.ContiguousMaskHint,
			hints.NonceHint,
			hints.Base64LenHint,
		)),
	)
}

func generateKeypair() (privateKey *ecdsa.PrivateKey, publicKeyECDSA *ecdsa.PublicKey, address common.Address) {
	// Use a fixed private key for testing
	privateKeyBytes, err := hex.DecodeString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	if err != nil {
		panic(err)
	}
	privateKey, err = crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		panic(err)
	}

	// Get the public key from the private key
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		panic("failed to get public key")
	}

	address = crypto.PubkeyToAddress(*publicKeyECDSA)

	return
}
