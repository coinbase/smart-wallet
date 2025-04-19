package circuits

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/mdehoog/poseidon/poseidon"

	"github.com/coinbase/smart-wallet/circuits/circuits/hints"
	"github.com/coinbase/smart-wallet/circuits/circuits/jwt"
	"github.com/coinbase/smart-wallet/circuits/circuits/rsa"
	"github.com/coinbase/smart-wallet/circuits/utils"
)

func TestZkLoginV2(t *testing.T) {
	assert := test.NewAssert(t)

	witnessEphemeralPublicKey, jwtRandomness, witnessJwtHeaderJson, witnessJwtPayloadJson, witnessKidValue, witnessIssValue, witnessAudValue, witnessSubValue, witnessJwtSignature, witnessIdpPublicKeyN := generateWitness()

	assert.ProverSucceeded(
		&ZkLoginCircuit[rsa.Mod1e2048]{
			// Public inputs sizes.
			EphemeralPublicKey: make([]frontend.Variable, MaxEphemeralPublicKeyChunks),
			JwtHeaderJson:      make([]uints.U8, jwt.MaxHeaderJsonLen),
			KidValue:           make([]uints.U8, jwt.MaxKidValueLen),

			// Private inputs sizes.
			JwtPayloadJson: make([]uints.U8, jwt.MaxPayloadJsonLen),
			IssValue:       make([]uints.U8, jwt.MaxIssValueLen),
			AudValue:       make([]uints.U8, jwt.MaxAudValueLen),
			SubValue:       make([]uints.U8, jwt.MaxSubValueLen),
		},
		&ZkLoginCircuit[rsa.Mod1e2048]{
			// Public inputs.
			IdpPublicKeyN:      witnessIdpPublicKeyN,
			EphemeralPublicKey: witnessEphemeralPublicKey,
			JwtHeaderJson:      witnessJwtHeaderJson,
			KidValue:           witnessKidValue,

			// Private inputs.
			JwtRandomness:  jwtRandomness,
			JwtPayloadJson: witnessJwtPayloadJson,
			IssValue:       witnessIssValue,
			AudValue:       witnessAudValue,
			SubValue:       witnessSubValue,
			JwtSignature:   witnessJwtSignature,
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

func generateWitness() (
	witnessEphemeralPublicKey []frontend.Variable,
	jwtRandomness *big.Int,

	witnessJwtHeaderJson []uints.U8,
	witnessJwtPayloadJson []uints.U8,

	witnessKidValue []uints.U8,

	witnessIssValue []uints.U8,
	witnessAudValue []uints.U8,
	witnessSubValue []uints.U8,

	witnessJwtSignature emulated.Element[rsa.Mod1e2048],
	witnessIdpPublicKeyN emulated.Element[rsa.Mod1e2048],
) {
	_, publicKey, _ := generateKeypair()

	ephemeralPublicKeyAsElements, err := utils.BytesTo31Chunks(crypto.FromECDSAPub(publicKey))
	if err != nil {
		panic(err)
	}

	witnessEphemeralPublicKey = make([]frontend.Variable, MaxEphemeralPublicKeyChunks)
	for i := range ephemeralPublicKeyAsElements {
		witnessEphemeralPublicKey[i] = frontend.Variable(ephemeralPublicKeyAsElements[i])
	}

	randBytes := make([]byte, ElementSize)
	_, err = rand.Read(randBytes)
	if err != nil {
		panic(err)
	}
	jwtRandomness = new(big.Int).SetUint64(42)

	inputBytes := append(ephemeralPublicKeyAsElements[:], jwtRandomness)
	nonce, err := poseidon.Hash[*bn254fr.Element](inputBytes)
	if err != nil {
		panic(err)
	}
	nonceBytes := nonce.Bytes()
	nonceBase64 := fmt.Sprintf(`"%s"`, base64.RawURLEncoding.EncodeToString(nonceBytes))

	kidValue, _, witnessKidValue := buildWitness(`"c37da75c9fbe18c2ce9125b9aa1f300dcb31e8d9"`, jwt.MaxKidValueLen)
	headerJson, _, witnessJwtHeaderJson := buildWitness(`{"alg":"RS256","kid":`+kidValue+`,"typ":"JWT"}`, jwt.MaxHeaderJsonLen)

	iss, _, witnessIssValue := buildWitness(`"https://accounts.google.com"`, jwt.MaxIssValueLen)
	aud, _, witnessAudValue := buildWitness(`"875735819865-ictb0rltgphgvhrgm125n5ch366tq8pv.apps.googleusercontent.com"`, jwt.MaxAudValueLen)
	sub, _, witnessSubValue := buildWitness(`"113282815992720230663"`, jwt.MaxSubValueLen)
	payloadJson, _, witnessJwtPayloadJson := buildWitness(`{"iss":`+iss+`,"azp":"875735819865-ictb0rltgphgvhrgm125n5ch366tq8pv.apps.googleusercontent.com","aud":`+aud+`,"sub":`+sub+`,"at_hash":"eS0K1c2No-I08aMu5M1NVw","nonce":`+nonceBase64+`,"iat":1745012349,"exp":1745015949}`, jwt.MaxPayloadJsonLen)

	headerBase64 := base64.RawURLEncoding.EncodeToString([]byte(headerJson))
	payloadBase64 := base64.RawURLEncoding.EncodeToString([]byte(payloadJson))

	packedBase64 := headerBase64 + "." + payloadBase64
	sha256.Sum256([]byte(packedBase64))

	signatureBase64 := "STWGikhlYClkv5UM_fBFSI9LuPY1vyc3hUs-oshZQFBE6Peq6kxbEpNX4jgqmOJUc_HhxT1lqjqufRKOI5bCq7oAjNSgT3pVNJFNoyeT9LBXrOfWydUb81ld3yVzYaZY7XtZSRjiRTjSy7LKjFAZwyqQY2QEnajtWBgdznQ196B0YKTfzh3skAbR1B9eJx_12idjNjgfw82eYk5uMrG3IxGKMh91ApEocTeC2mEP1_6r1aL_EbrxU7sZtd_5Vqu_5vdYOa7pu5aTPyHOqr-s-DnvWQqnz76fX0tVO-qWAFoocs-EPFWftb1RJnK2V-1dEirCICjyySSVq4YnpujPRA"
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		panic(err)
	}
	signature := new(big.Int).SetBytes(signatureBytes)
	witnessJwtSignature = emulated.ValueOf[rsa.Mod1e2048](signature)

	idpPublicKeyNBase64 := "vUiHFY8O45dBoYLGipsgaVOk7rGpim6CK1iPG2zSt3sO9-09S9dB5nQdIelGye-mouQXaW5U7H8lZnv5wLJ8VSzquaSh3zJkbDq-Wvgas6U-FJaMy35kiExr5gUKUGPAIjI2sLASDbFD0vT_jxtg0ZRknwkexz_gZadZQ-iFEO7unjpE_zQnx8LhN-3a8dRf2B45BLY5J9aQJi4Csa_NHzl9Ym4uStYraSgwW93VYJwDJ3wKTvwejPvlW3n0hUifvkMke3RTqnSDIbP2xjtNmj12wdd-VUw47-cor5lMn7LG400G7lmI8rUSEHIzC7UyzEW7y15_uzuqvIkFVTLXlQ"
	idpPublicKeyNBytes, err := base64.RawURLEncoding.DecodeString(idpPublicKeyNBase64)
	if err != nil {
		panic(err)
	}
	idpPublicKeyN := new(big.Int).SetBytes(idpPublicKeyNBytes)
	witnessIdpPublicKeyN = emulated.ValueOf[rsa.Mod1e2048](idpPublicKeyN)

	return
}

func generateKeypair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, common.Address) {
	// Use a fixed private key for testing
	privateKeyBytes, err := hex.DecodeString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	if err != nil {
		panic(err)
	}
	privateKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		panic(err)
	}

	// Get the public key from the private key
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		panic("failed to get public key")
	}

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

	return privateKey, publicKeyECDSA, address
}

func buildWitness(
	value string,
	maxLen int,
) (string, int, []uints.U8) {
	witness := make([]uints.U8, maxLen)
	for i := range value {
		witness[i] = uints.NewU8(value[i])
	}

	return value, len(value), witness
}
