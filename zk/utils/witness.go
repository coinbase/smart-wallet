package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/mdehoog/poseidon/poseidon"

	"github.com/coinbase/smart-wallet/circuits/circuits"
	"github.com/coinbase/smart-wallet/circuits/circuits/jwt"
)

func GenerateWitness[RSAFieldParams emulated.FieldParams](
	ephPubKey []byte,
	idpPubKeyNBase64 string,
	jwtHeaderJson string,
	jwtPayloadJson string,
	jwtSignatureBase64 string,
	jwtRandomness *big.Int,
	userSalt *big.Int,
) (
	witnessPublicHash *big.Int,

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
	witnessJwtRandomness *big.Int,
	witnessUserSalt *big.Int,

	err error,
) {
	idpPublicKeyNBytes, err := base64.RawURLEncoding.DecodeString(idpPubKeyNBase64)
	if err != nil {
		panic(err)
	}
	witnessIdpPubKeyN = emulated.ValueOf[RSAFieldParams](idpPublicKeyNBytes)

	ephPublicKeyAsElements := make([]*big.Int, circuits.MaxEphPubKeyChunks)
	for i := range ephPublicKeyAsElements {
		ephPublicKeyAsElements[i] = big.NewInt(0)
	}
	chunks, err := BytesTo31Chunks(ephPubKey)
	if err != nil {
		return
	}
	copy(ephPublicKeyAsElements, chunks)

	for i := range ephPublicKeyAsElements {
		witnessEphPubKey[i] = frontend.Variable(ephPublicKeyAsElements[i])
	}

	var jwtHeader map[string]json.RawMessage
	if err = json.Unmarshal([]byte(jwtHeaderJson), &jwtHeader); err != nil {
		return
	}

	witnessJwtHeaderJson, witnessKidValue, err = buildJsonHeaderWitnesses(jwtHeaderJson, string(jwtHeader["kid"]))
	if err != nil {
		return
	}

	var jwtPayload map[string]json.RawMessage
	if err = json.Unmarshal([]byte(jwtPayloadJson), &jwtPayload); err != nil {
		return
	}

	zkAddr, err := deriveZkAddr(
		jwtPayload["iss"],
		jwtPayload["aud"],
		jwtPayload["sub"],
		userSalt,
	)
	if err != nil {
		return
	}
	witnessZkAddr = new(big.Int).Set(zkAddr)

	witnessJwtPayloadJson, witnessIssValue, witnessAudValue, witnessSubValue, err = buildJsonPayloadWitnesses(jwtPayloadJson, string(jwtPayload["iss"]), string(jwtPayload["aud"]), string(jwtPayload["sub"]))
	if err != nil {
		return
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(jwtSignatureBase64)
	if err != nil {
		return
	}
	witnessJwtSignature = emulated.ValueOf[RSAFieldParams](signatureBytes)

	witnessPublicHash, err = hashPublicInputs[RSAFieldParams](
		idpPublicKeyNBytes,
		ephPublicKeyAsElements,
		zkAddr,
	)
	if err != nil {
		return
	}

	witnessJwtRandomness = new(big.Int).Set(jwtRandomness)
	witnessUserSalt = new(big.Int).Set(userSalt)

	// Safety checks to make sure the JWT nonce was computed correctly
	inputBytes := append(ephPublicKeyAsElements[:], jwtRandomness)
	expectedNonce, err := poseidon.Hash[*bn254fr.Element](inputBytes)
	if err != nil {
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

func hashPublicInputs[FieldParams emulated.FieldParams](
	idpPublicKeyNBytes []byte,
	ephPublicKeyAsElements []*big.Int,
	zkAddr *big.Int,
) (hash *big.Int, err error) {
	idpPublicKeyNLimbs := bytesToLimbs[FieldParams](idpPublicKeyNBytes)

	inputs := make([]*big.Int, len(idpPublicKeyNLimbs)+circuits.MaxEphPubKeyChunks+1)
	for i := range inputs {
		inputs[i] = big.NewInt(0)
	}

	copy(inputs[0:], idpPublicKeyNLimbs)
	offset := len(idpPublicKeyNLimbs)

	copy(inputs[offset:], ephPublicKeyAsElements)
	offset += len(ephPublicKeyAsElements)

	inputs[offset] = zkAddr

	hash, err = poseidon.HashMulti[*bn254fr.Element](inputs)

	return
}

func bytesToLimbs[FieldParams emulated.FieldParams](bytes []byte) (limbs []*big.Int) {
	var fp FieldParams
	l := int(fp.NbLimbs())
	limbs = make([]*big.Int, l)
	bytesPerLimb := int(fp.BitsPerLimb() / 8)

	for i := range limbs {
		limb := new(big.Int).SetBytes(bytes[i*bytesPerLimb : (i+1)*bytesPerLimb])
		limbs[l-1-i] = limb
	}

	return
}

func deriveZkAddr(iss, aud, sub []byte, userSalt *big.Int) (zkAddr *big.Int, err error) {
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
