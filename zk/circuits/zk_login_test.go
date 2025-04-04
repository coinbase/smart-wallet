package circuits

import (
	"crypto/rand"
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

	newOwner := []byte("some_ethereum_address")

	// {"typ":"JWT","alg":"RS256","kid":"1234567890"}
	jwtHeaderKidValue := `"1234567890"`
	jwtHeaderJson := fmt.Sprintf(
		`{"typ":"JWT","alg":"RS256","kid":%s}`,
		jwtHeaderKidValue,
	)
	jwtHeaderBase64 := base64.RawURLEncoding.EncodeToString([]byte(jwtHeaderJson))

	// {"iss":"google.com","aud":"csw.com","sub":"xenoliss","nonce":"c29tZV9ldGhlcmV1bV9hZGRyZXNz"}
	iss := `"google.com"`
	aud := `"csw.com"`
	sub := `"xenoliss"`
	nonce := fmt.Sprintf(`"%s"`, base64.RawURLEncoding.EncodeToString(newOwner))
	jwtPayloadJson := fmt.Sprintf(
		`{"iss":%s,"aud":%s,"sub":%s,"nonce":%s}`,
		iss,
		aud,
		sub,
		nonce,
	)
	fmt.Println("JWT payload:", jwtPayloadJson)
	jwtPayloadBase64 := base64.RawURLEncoding.EncodeToString([]byte(jwtPayloadJson))

	userSalt := make([]byte, UserSaltLen)
	_, err := rand.Read(userSalt)
	if err != nil {
		t.Fatalf("failed to generate user salt: %v", err)
	}

	witnessNonce := make([]uints.U8, MaxNonceLen)
	for i := range nonce {
		witnessNonce[i] = uints.NewU8(nonce[i])
	}

	witnessJwtHeaderBase64 := make([]uints.U8, MaxJwtHeaderLenBase64)
	for i := range jwtHeaderBase64 {
		witnessJwtHeaderBase64[i] = uints.NewU8(jwtHeaderBase64[i])
	}

	witnessJwtPayloadJson := make([]uints.U8, MaxJwtPayloadJsonLen)
	for i := range jwtPayloadJson {
		witnessJwtPayloadJson[i] = uints.NewU8(jwtPayloadJson[i])
	}

	witnessUserSalt := make([]uints.U8, UserSaltLen)
	for i := range userSalt {
		witnessUserSalt[i] = uints.NewU8(userSalt[i])
	}

	bytes := make([]uint8, MaxIssLen+MaxAudLen+MaxSubLen+UserSaltLen)
	copy(bytes, iss)
	copy(bytes[MaxIssLen:], aud)
	copy(bytes[MaxIssLen+MaxAudLen:], sub)
	copy(bytes[MaxIssLen+MaxAudLen+MaxSubLen:], userSalt)
	zkAddrBytes := sha256.Sum256(bytes)
	zkAddr := new(big.Int).SetBytes(zkAddrBytes[1:]) // Skip the first byte (big endian) to fit the BN254 scalar field.

	jwtBase64 := fmt.Sprintf("%s.%s", jwtHeaderBase64, jwtPayloadBase64)
	jwtHashBytes := sha256.Sum256([]byte(jwtBase64))
	jwtHash := new(big.Int).SetBytes(jwtHashBytes[1:]) // Skip the first byte (big endian) to fit the BN254 scalar field.

	assert.ProverSucceeded(
		&ZkLoginCircuit{
			// Set public inputs sizes.
			JwtHeaderBase64: make([]uints.U8, MaxJwtHeaderLenBase64),
			Nonce:           make([]uints.U8, MaxNonceLen),

			// Set private inputs sizes.
			JwtPayloadJson: make([]uints.U8, MaxJwtPayloadJsonLen),
			UserSalt:       make([]uints.U8, UserSaltLen),
		},
		&ZkLoginCircuit{
			// Public inputs.
			JwtHeaderBase64: witnessJwtHeaderBase64,
			Nonce:           witnessNonce,
			JwtHash:         jwtHash,
			ZkAddr:          zkAddr,

			// Semi-private inputs.
			JwtHeaderBase64Len: len(jwtHeaderBase64),
			NonceOffset:        strings.Index(jwtPayloadJson, `"nonce"`),
			NonceLen:           len(nonce),

			// Private inputs.
			JwtPayloadJson:      witnessJwtPayloadJson,
			JwtPayloadBase64Len: len(jwtPayloadBase64),

			IssOffset: strings.Index(jwtPayloadJson, `"iss"`),
			IssLen:    len(iss),
			AudOffset: strings.Index(jwtPayloadJson, `"aud"`),
			AudLen:    len(aud),
			SubOffset: strings.Index(jwtPayloadJson, `"sub"`),
			SubLen:    len(sub),

			UserSalt: witnessUserSalt,
		},
		test.WithCurves(ecc.BN254),
	)
}
