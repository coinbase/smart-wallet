package circuits_test

import (
	"crypto/ecdsa"
	"encoding/hex"
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

	// Info taken from running the zk-demo app.
	ephPubKeyHex := "0x0cbE8d89B0ED8e575f029F856D6c818b02926ac0"
	idpPubKeyNBase64 := "jb7Wtq9aDMpiXvHGCB5nrfAS2UutDEkSbK16aDtDhbYJhDWhd7vqWhFbnP0C_XkSxsqWJoku69y49EzgabEiUMf0q3X5N0pNvV64krviH2m9uLnyGP5GMdwZpjTXARK9usGgYZGuWhjfgTTvooKDUdqVQYvbrmXlblkM6xjbA8GnShSaOZ4AtMJCjWnaN_UaMD_vAXvOYj4SaefDMSlSoiI46yipFdggfoIV8RDg1jeffyre_8DwOWsGz7b2yQrL7grhYCvoiPrybKmViXqu-17LTIgBw6TDk8EzKdKzm33_LvxU7AKs3XWW_NvZ4WCPwp4gr7uw6RAkdDX_ZAn0TQ"
	jwtHeaderJson := `{"alg":"RS256","kid":"23f7a3583796f97129e5418f9b2136fcc0a96462","typ":"JWT"}`
	jwtPayloadJson := `{"iss":"https://accounts.google.com","azp":"875735819865-ictb0rltgphgvhrgm125n5ch366tq8pv.apps.googleusercontent.com","aud":"875735819865-ictb0rltgphgvhrgm125n5ch366tq8pv.apps.googleusercontent.com","sub":"113282815992720230663","at_hash":"Z5sFXDjIjrLAVFHeVZzcZA","nonce":"HBTIKWFNIabRB1inoG1jsfrXHam0OMkTfJ2eOPXK4II","iat":1745225957,"exp":1745229557}`
	jwtSignatureBase64 := "Dq3WcN5BITPpIqJxItEsSmiTTo81I6UfNB-9mbXAXLNhsMCcqOI54PtMXVEzIT6hh87yEpyJ4qhj-Fixxxma7_XFaKiwBrqwYIqyymdMhSapwkWXK4NLQO0NnP-e_BPtSDilUS1D_AJa7cZC93Pc0-cACa8pJIZPiwmygqmkwmHxZrWN23cjhZkwA3zorJ2ZzyRjgpOQOk9nX9kXs9A3FP096uWPjh2ICfNrVG8uEbo6FA_COBBfRR5Rql8ZkR80lUTaGAaHaHTS2ELd0c26qYRrvfBAGMMnn6Xij-TCp_jYhwDGBfIAmCtSuunN9xmbk2dRRI7DgXuHRH4XxSf1IA"
	jwtRndHex := "0xde75dbbf8c5bb88b0f30e821576202b065c33525a4f34528019f4e89ec0920"
	userSaltHex := "0xcec61e0368523a044fc7b3138b65869aa4c58694f1fb4dd273873d87d24986"

	assignment, _, err := utils.GenerateWitness[rsa.Mod1e2048](
		ephPubKeyHex,
		idpPubKeyNBase64,
		jwtHeaderJson,
		jwtPayloadJson,
		jwtSignatureBase64,
		jwtRndHex,
		userSaltHex,
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
		assignment,
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
