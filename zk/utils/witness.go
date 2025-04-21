package utils

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/mdehoog/poseidon/poseidon"

	"github.com/coinbase/smart-wallet/circuits/circuits"
	"github.com/coinbase/smart-wallet/circuits/circuits/jwt"
)

func DeriveNonce(ephPublicKeyAsElements []*big.Int, jwtRnd *big.Int) (nonce *big.Int, err error) {
	inputBytes := append(ephPublicKeyAsElements[:], jwtRnd)
	nonce, err = poseidon.Hash[*bn254fr.Element](inputBytes)

	return
}

func DeriveZkAddr(iss, aud, sub string, userSalt *big.Int) (zkAddr *big.Int, err error) {
	inputs := make([]*big.Int, jwt.MaxIssValueLen+jwt.MaxAudValueLen+jwt.MaxSubValueLen+1)
	for i := range inputs {
		inputs[i] = big.NewInt(0)
	}

	for i := range iss {
		inputs[i] = big.NewInt(int64(iss[i]))
	}
	offset := jwt.MaxIssValueLen

	for i := range aud {
		inputs[offset+i] = big.NewInt(int64(aud[i]))
	}
	offset += jwt.MaxAudValueLen

	for i := range sub {
		inputs[offset+i] = big.NewInt(int64(sub[i]))
	}
	offset += jwt.MaxSubValueLen

	inputs[offset] = userSalt

	zkAddr, err = poseidon.HashMulti[*bn254fr.Element](inputs)

	return
}

func EphPubKeyToElements(ephPubKey []byte) (ephPublicKeyAsElements []*big.Int, err error) {
	ephPublicKeyAsElements = make([]*big.Int, circuits.MaxEphPubKeyChunks)
	for i := range ephPublicKeyAsElements {
		ephPublicKeyAsElements[i] = big.NewInt(0)
	}

	elements, err := BytesToElements(ephPubKey, circuits.ElementSize)
	if err != nil {
		err = fmt.Errorf("failed to convert ephemeral public key to 31-byte elements: %w", err)
		return
	}

	copy(ephPublicKeyAsElements, elements)

	return
}

func GenerateWitness[RSAFieldParams emulated.FieldParams](
	ephPubKeyHex string,
	idpPubKeyNBase64 string,
	jwtHeaderJson string,
	jwtPayloadJson string,
	jwtSignatureBase64 string,
	jwtRndHex string,
	userSaltHex string,
) (assignment *circuits.ZkLoginCircuit[RSAFieldParams], w witness.Witness, err error) {
	// Parse the ephemeral public key.
	ephPubKey, err := hex.DecodeString(strings.TrimPrefix(ephPubKeyHex, "0x"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode ephemeral public key: %w", err)
	}

	// Parse the JWT randomness.
	jwtRndBytes, err := hex.DecodeString(strings.TrimPrefix(jwtRndHex, "0x"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode JWT randomness: %w", err)
	}
	jwtRnd := new(big.Int).SetBytes(jwtRndBytes)

	// Parse the user salt.
	userSaltBytes, err := hex.DecodeString(strings.TrimPrefix(userSaltHex, "0x"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode user salt: %w", err)
	}
	userSalt := new(big.Int).SetBytes(userSaltBytes)

	witnessIdpPubKeyN, witnessEphPubKey, witnessJwtHeaderJson, witnessKidValue, witnessZkAddr, witnessJwtPayloadJson, witnessIssValue, witnessAudValue, witnessSubValue, witnessJwtSignature, witnessJwtRnd, witnessUserSalt, err := generateWitnesses[RSAFieldParams](
		ephPubKey,
		idpPubKeyNBase64,
		jwtHeaderJson,
		jwtPayloadJson,
		jwtSignatureBase64,
		jwtRnd,
		userSalt,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate witness: %w", err)
	}

	assignment = &circuits.ZkLoginCircuit[RSAFieldParams]{
		// Public inputs.
		IdpPubKeyN: witnessIdpPubKeyN,
		EphPubKey:  witnessEphPubKey,
		ZkAddr:     witnessZkAddr,

		// Private non-sensitive inputs.
		JwtHeaderJson: witnessJwtHeaderJson,
		KidValue:      witnessKidValue,

		// Private sensitive inputs.
		JwtPayloadJson: witnessJwtPayloadJson,
		IssValue:       witnessIssValue,
		AudValue:       witnessAudValue,
		SubValue:       witnessSubValue,
		JwtSignature:   witnessJwtSignature,
		JwtRnd:         witnessJwtRnd,
		UserSalt:       witnessUserSalt,
	}

	w, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create witness: %w", err)
	}

	return
}

func generateWitnesses[RSAFieldParams emulated.FieldParams](
	ephPubKey []byte,
	idpPubKeyNBase64 string,
	jwtHeaderJson string,
	jwtPayloadJson string,
	jwtSignatureBase64 string,
	jwtRnd *big.Int,
	userSalt *big.Int,
) (
	witnessIdpPubKeyN emulated.Element[RSAFieldParams],
	witnessEphPubKey [circuits.MaxEphPubKeyChunks]frontend.Variable,
	witnessJwtHeaderJson []uints.U8,
	witnessKidValue []uints.U8,
	witnessZkAddr frontend.Variable,

	witnessJwtPayloadJson []uints.U8,
	witnessIssValue []uints.U8,
	witnessAudValue []uints.U8,
	witnessSubValue []uints.U8,
	witnessJwtSignature emulated.Element[RSAFieldParams],
	witnessJwtRnd *big.Int,
	witnessUserSalt *big.Int,

	err error,
) {
	idpPublicKeyNBytes, err := base64.RawURLEncoding.DecodeString(idpPubKeyNBase64)
	if err != nil {
		panic(err)
	}
	witnessIdpPubKeyN = emulated.ValueOf[RSAFieldParams](idpPublicKeyNBytes)

	ephPublicKeyAsElements, err := EphPubKeyToElements(ephPubKey)
	if err != nil {
		err = fmt.Errorf("failed to convert ephemeral public key to 31-byte chunks: %w", err)
		return
	}

	for i := range ephPublicKeyAsElements {
		witnessEphPubKey[i] = frontend.Variable(ephPublicKeyAsElements[i])
	}

	var jwtHeader map[string]json.RawMessage
	if err = json.Unmarshal([]byte(jwtHeaderJson), &jwtHeader); err != nil {
		err = fmt.Errorf("failed to unmarshal JWT header JSON: %w", err)
		return
	}

	witnessJwtHeaderJson, witnessKidValue, err = buildJsonHeaderWitnesses(jwtHeaderJson, string(jwtHeader["kid"]))
	if err != nil {
		err = fmt.Errorf("failed to build JSON header witnesses: %w", err)
		return
	}

	var jwtPayload map[string]json.RawMessage
	if err = json.Unmarshal([]byte(jwtPayloadJson), &jwtPayload); err != nil {
		err = fmt.Errorf("failed to unmarshal JWT payload JSON: %w", err)
		return
	}

	zkAddr, err := DeriveZkAddr(
		string(jwtPayload["iss"]),
		string(jwtPayload["aud"]),
		string(jwtPayload["sub"]),
		userSalt,
	)
	if err != nil {
		err = fmt.Errorf("failed to derive ZK address: %w", err)
		return
	}
	witnessZkAddr = new(big.Int).Set(zkAddr)

	witnessJwtPayloadJson, witnessIssValue, witnessAudValue, witnessSubValue, err = buildJsonPayloadWitnesses(jwtPayloadJson, string(jwtPayload["iss"]), string(jwtPayload["aud"]), string(jwtPayload["sub"]))
	if err != nil {
		err = fmt.Errorf("failed to build JSON payload witnesses: %w", err)
		return
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(jwtSignatureBase64)
	if err != nil {
		err = fmt.Errorf("failed to decode JWT signature: %w", err)
		return
	}
	witnessJwtSignature = emulated.ValueOf[RSAFieldParams](signatureBytes)

	witnessJwtRnd = new(big.Int).Set(jwtRnd)
	witnessUserSalt = new(big.Int).Set(userSalt)

	// Safety checks to make sure the JWT nonce was computed correctly
	expectedNonce, err := DeriveNonce(ephPublicKeyAsElements, jwtRnd)
	if err != nil {
		err = fmt.Errorf("failed to hash JWT nonce: %w", err)
		return
	}
	expectedNonceBase64 := fmt.Sprintf(`"%s"`, base64.RawURLEncoding.EncodeToString(expectedNonce.Bytes()))
	if expectedNonceBase64 != string(jwtPayload["nonce"]) {
		err = fmt.Errorf("invalid nonce: computed %s, extracted %s", expectedNonceBase64, string(jwtPayload["nonce"]))
		return
	}

	return
}

func buildJsonHeaderWitnesses(jwtHeaderJson, kidValue string) (witnessJwtHeaderJson, witnessKidValue []uints.U8, err error) {
	if len(jwtHeaderJson) > jwt.MaxHeaderJsonLen {
		err = fmt.Errorf("invalid header JSON length: %d (max %d)", len(witnessJwtHeaderJson), jwt.MaxHeaderJsonLen)
		return
	}
	witnessJwtHeaderJson = buildWitnessU8Slice(jwtHeaderJson, jwt.MaxHeaderJsonLen)

	if len(kidValue) > jwt.MaxKidValueLen {
		err = fmt.Errorf("invalid kid value length: %d (max %d)", len(kidValue), jwt.MaxKidValueLen)
		return
	}
	witnessKidValue = buildWitnessU8Slice(kidValue, jwt.MaxKidValueLen)

	return
}

func buildJsonPayloadWitnesses(jwtPayloadJson, issValue, audValue, subValue string) (witnessJwtPayloadJson, witnessIssValue, witnessAudValue, witnessSubValue []uints.U8, err error) {
	if len(jwtPayloadJson) > jwt.MaxPayloadJsonLen {
		err = fmt.Errorf("invalid payload JSON length: %d (max %d)", len(jwtPayloadJson), jwt.MaxPayloadJsonLen)
		return
	}
	witnessJwtPayloadJson = buildWitnessU8Slice(jwtPayloadJson, jwt.MaxPayloadJsonLen)

	if len(issValue) > jwt.MaxIssValueLen {
		err = fmt.Errorf("invalid iss value length: %d (max %d)", len(issValue), jwt.MaxIssValueLen)
		return
	}
	witnessIssValue = buildWitnessU8Slice(issValue, jwt.MaxIssValueLen)

	if len(audValue) > jwt.MaxAudValueLen {
		err = fmt.Errorf("invalid aud value length: %d (max %d)", len(audValue), jwt.MaxAudValueLen)
		return
	}
	witnessAudValue = buildWitnessU8Slice(audValue, jwt.MaxAudValueLen)

	if len(subValue) > jwt.MaxSubValueLen {
		err = fmt.Errorf("invalid sub value length: %d (max %d)", len(subValue), jwt.MaxSubValueLen)
		return
	}
	witnessSubValue = buildWitnessU8Slice(subValue, jwt.MaxSubValueLen)

	return
}

func buildWitnessU8Slice(value string, maxLen int) (witness []uints.U8) {
	witness = make([]uints.U8, maxLen)
	for i := range value {
		witness[i] = uints.NewU8(value[i])
	}

	return
}
