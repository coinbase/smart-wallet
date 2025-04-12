package circuits

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/coinbase/smart-wallet/circuits/circuits/v2/hints"
	"github.com/coinbase/smart-wallet/circuits/circuits/v2/jwt"
	"github.com/coinbase/smart-wallet/circuits/utils"

	"github.com/consensys/gnark-crypto/ecc"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/mdehoog/poseidon/poseidon"
)

func TestZkLoginV2(t *testing.T) {
	assert := test.NewAssert(t)

	witnessPublicKey, jwtRandomness, witnessJwtHeaderJson, witnessJwtPayloadJson, witnessKidValue, witnessIssValue, witnessAudValue, witnessSubValue := generateWitness()

	assert.ProverSucceeded(
		&ZkLoginCircuitV2{
			// Public inputs sizes.
			PublicKey:     make([]frontend.Variable, MaxPublicKeyChunks),
			JwtHeaderJson: make([]uints.U8, jwt.MaxHeaderJsonLen),
			KidValue:      make([]uints.U8, jwt.MaxKidValueLen),

			// Private inputs sizes.
			JwtPayloadJson: make([]uints.U8, jwt.MaxPayloadJsonLen),
			IssValue:       make([]uints.U8, jwt.MaxIssValueLen),
			AudValue:       make([]uints.U8, jwt.MaxAudValueLen),
			SubValue:       make([]uints.U8, jwt.MaxSubValueLen),
		},
		&ZkLoginCircuitV2{
			// Public inputs.
			PublicKey:     witnessPublicKey,
			JwtHeaderJson: witnessJwtHeaderJson,
			KidValue:      witnessKidValue,

			// Private inputs.
			JwtRandomness:  jwtRandomness,
			JwtPayloadJson: witnessJwtPayloadJson,
			IssValue:       witnessIssValue,
			AudValue:       witnessAudValue,
			SubValue:       witnessSubValue,
		},
		test.WithCurves(ecc.BN254),
		test.WithSolverOpts(solver.WithHints(
			hints.OffsetHint,
			hints.ValueLenHint,
			hints.MaskHint,
			hints.NonceHint,
		)),
	)
}

func generateWitness() (
	witnessPublicKey []frontend.Variable,
	jwtRandomness *big.Int,

	witnessJwtHeaderJson []uints.U8,
	witnessJwtPayloadJson []uints.U8,

	witnessKidValue []uints.U8,

	witnessIssValue []uints.U8,
	witnessAudValue []uints.U8,
	witnessSubValue []uints.U8,
) {
	_, publicKey, _ := generateKeypair()

	pkAsElements, err := utils.BytesTo31Chunks(crypto.FromECDSAPub(publicKey))
	if err != nil {
		panic(err)
	}

	witnessPublicKey = make([]frontend.Variable, MaxPublicKeyChunks)
	for i := range pkAsElements {
		witnessPublicKey[i] = frontend.Variable(pkAsElements[i])
	}

	randBytes := make([]byte, ElementSize)
	_, err = rand.Read(randBytes)
	if err != nil {
		panic(err)
	}
	jwtRandomness = new(big.Int).SetBytes(randBytes)

	inputBytes := append(pkAsElements[:], jwtRandomness)
	nonce, err := poseidon.Hash[*bn254fr.Element](inputBytes)
	if err != nil {
		panic(err)
	}
	nonceBytes := nonce.Bytes()
	fmt.Printf("nonce: %v\n", nonceBytes)

	kidValue, _, witnessKidValue := buildWitness(`"c7e04465649ffa606557650c7e65f0a87ae00fe8"`, jwt.MaxKidValueLen)
	_, _, witnessJwtHeaderJson = buildWitness(`{"alg":"RS256","kid":`+kidValue+`,"typ":"JWT"}`, jwt.MaxHeaderJsonLen)

	iss, _, witnessIssValue := buildWitness(`"https://accounts.google.com"`, jwt.MaxIssValueLen)
	aud, _, witnessAudValue := buildWitness(`"875735819865-ictb0rltgphgvhrgm125n5ch366tq8pv.apps.googleusercontent.com"`, jwt.MaxAudValueLen)
	sub, _, witnessSubValue := buildWitness(`"113282815992720230663"`, jwt.MaxSubValueLen)
	_, _, witnessJwtPayloadJson = buildWitness(`{"iss":`+iss+`,"azp":"875735819865-ictb0rltgphgvhrgm125n5ch366tq8pv.apps.googleusercontent.com","aud":`+aud+`,"sub":`+sub+`,"at_hash":"9AyUC82Dvc4xVfVhgRIlsA","nonce":"AAAAAAAAAAAAAAAAPwVSlDKL0A4iKV6q_v_TLiuV9to","iat":1744393026,"exp":1744396626}`, jwt.MaxPayloadJsonLen)

	return
}

func generateKeypair() (*ecdsa.PrivateKey, *ecdsa.PublicKey, common.Address) {
	privateKey, err := crypto.GenerateKey()
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
