package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"github.com/coinbase/smart-wallet/circuits/circuits"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
)

func main() {
	zkCircuit := circuits.ZkLoginCircuit{
		// Set public inputs values.
		JwtHeaderKidValue: make([]uints.U8, circuits.MaxJwtHeaderKidValueLen),

		// Set private inputs sizes.
		JwtHeader:  make([]uints.U8, circuits.MaxJwtHeaderLen),
		JwtPayload: make([]uints.U8, circuits.MaxJwtPayloadLen),
	}

	fmt.Println("Compiling...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &zkCircuit)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Compilation done. %d constraints.\n", cs.GetNbConstraints())

	fmt.Println("Setting up Groth16 parameters...")
	pk, err := groth16.DummySetup(cs)
	if err != nil {
		panic(err)
	}
	fmt.Println("Groth16 parameters set up")

	fmt.Println("Generating witness...")
	witness := generateWitness()
	fmt.Println("Witness generated")

	fmt.Println("Proving...")
	_, err = groth16.Prove(cs, pk, witness)
	if err != nil {
		panic(err)
	}
	fmt.Println("Proof generated")

	// fmt.Println("Verifying...")
	// err = groth16.Verify(proof, vk, publicWitness)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Println("Proof is valid")
}

func generateWitness() witness.Witness {
	// {"typ":"JWT","alg":"RSA","kid":"1234567890"}
	jwtHeaderKidValue := `"1234567890"`
	jwtHeader := fmt.Sprintf(
		`{"typ":"JWT","alg":"RSA","kid":%s}`,
		jwtHeaderKidValue,
	)
	jwtHeaderBase64 := base64.RawURLEncoding.EncodeToString([]byte(jwtHeader))

	// {"iss":"google.com","aud":"csw.com","sub":"xenoliss"}
	jwtPayloadIssValue := `"google.com"`
	jwtPayloadAudValue := `"csw.com"`
	jwtPayloadSubValue := `"xenoliss"`
	jwtPayload := fmt.Sprintf(
		`{"iss":%s,"aud":%s,"sub":%s}`,
		jwtPayloadIssValue,
		jwtPayloadAudValue,
		jwtPayloadSubValue,
	)
	jwtPayloadBase64 := base64.RawURLEncoding.EncodeToString([]byte(jwtPayload))

	witnessJwtHeader := make([]uints.U8, circuits.MaxJwtHeaderLen)
	for i := range jwtHeader {
		witnessJwtHeader[i] = uints.NewU8(jwtHeader[i])
	}

	witnessJwtHeaderKidValue := make([]uints.U8, circuits.MaxJwtHeaderKidValueLen)
	for i := range jwtHeaderKidValue {
		witnessJwtHeaderKidValue[i] = uints.NewU8(jwtHeaderKidValue[i])
	}

	witnessJwtPayload := make([]uints.U8, circuits.MaxJwtPayloadLen)
	for i := range jwtPayload {
		witnessJwtPayload[i] = uints.NewU8(jwtPayload[i])
	}

	bytes := make([]uint8, circuits.MaxJwtPayloadIssLen+circuits.MaxJwtPayloadAudLen+circuits.MaxJwtPayloadSubLen)
	copy(bytes, jwtPayloadIssValue)
	copy(bytes[circuits.MaxJwtPayloadIssLen:], jwtPayloadAudValue)
	copy(bytes[circuits.MaxJwtPayloadIssLen+circuits.MaxJwtPayloadAudLen:], jwtPayloadSubValue)
	derivedHashBytes := sha256.Sum256(bytes)
	derivedHash := new(big.Int).SetBytes(derivedHashBytes[1:]) // Skip the first byte (big endian) to fit the BN254 scalar field.

	jwtBase64 := fmt.Sprintf("%s.%s", jwtHeaderBase64, jwtPayloadBase64)
	jwtHashBytes := sha256.Sum256([]byte(jwtBase64))
	jwtHash := new(big.Int).SetBytes(jwtHashBytes[1:]) // Skip the first byte (big endian) to fit the BN254 scalar field.

	assignment := &circuits.ZkLoginCircuit{
		// // Public inputs.
		JwtHeaderKidValue: witnessJwtHeaderKidValue,
		JwtHash:           jwtHash,
		DerivedHash:       derivedHash,

		// Private inputs.
		JwtHeader:           witnessJwtHeader,
		JwtHeaderBase64Len:  len(jwtHeaderBase64),
		JwtPayload:          witnessJwtPayload,
		JwtPayloadBase64Len: len(jwtPayloadBase64),

		TypOffset:   strings.Index(jwtHeader, `"typ"`),
		AlgOffset:   strings.Index(jwtHeader, `"alg"`),
		KidOffset:   strings.Index(jwtHeader, `"kid"`),
		KidValueLen: len(jwtHeaderKidValue),

		IssOffset:   strings.Index(jwtPayload, `"iss"`),
		IssValueLen: len(jwtPayloadIssValue),
		AudOffset:   strings.Index(jwtPayload, `"aud"`),
		AudValueLen: len(jwtPayloadAudValue),
		SubOffset:   strings.Index(jwtPayload, `"sub"`),
		SubValueLen: len(jwtPayloadSubValue),
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		panic(err)
	}
	return witness
}
