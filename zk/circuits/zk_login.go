package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/uints"
)

type ZkLoginCircuit struct {
	// // Public inputs
	// JwtHeaderKidValue []uints.U8        `gnark:",public"`
	// DerivedHash       frontend.Variable `gnark:",public"`
	JwtHash frontend.Variable `gnark:",public"`

	// Private inputs
	JwtHeader           []uints.U8
	JwtHeaderBase64Len  frontend.Variable
	JwtPayload          []uints.U8
	JwtPayloadBase64Len frontend.Variable

	// TypOffset, AlgOffset   frontend.Variable
	// KidOffset, KidValueLen frontend.Variable

	// IssOffset, IssValueLen frontend.Variable
	// AudOffset, AudValueLen frontend.Variable
	// SubOffset, SubValueLen frontend.Variable
}

func (c *ZkLoginCircuit) Define(api frontend.API) error {
	field, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	encodedJwtHeader := EncodeBase64URL(api, field, c.JwtHeader)
	encodedJwtPayload := EncodeBase64URL(api, field, c.JwtPayload)
	packedJwt := PackJwt(api, field, encodedJwtHeader, encodedJwtPayload, c.JwtHeaderBase64Len)

	// // 1. Decode the JWT base64 encoded string.
	// decodedJwt := decodeBase64URL(api, field, c.JwtBase64[:])

	// // 2. Verify the JWT content and extract the "iss", "aud" and "sub" fields.
	// ProcessJwtHeader(
	// 	api, decodedJwt[:MaxJwtHeaderLen],
	// 	c.TypOffset, c.AlgOffset,
	// 	c.KidOffset, c.KidValueLen, c.JwtHeaderKidValue,
	// )

	// ProcessJwtPayload(
	// 	api, field, decodedJwt,
	// 	c.IssOffset, c.IssValueLen,
	// 	c.AudOffset, c.AudValueLen,
	// 	c.SubOffset, c.SubValueLen,
	// )

	// // 3. Recompute the derived hash and compare it with the expected `DerivedHash`.
	// sha, err := sha2.New(api)
	// if err != nil {
	// 	return err
	// }

	// sha.Write(iss[:])
	// sha.Write(aud[:])
	// sha.Write(sub[:])
	// hashBytes := sha.Sum()
	// var hashBin []frontend.Variable
	// for i := 31; i > 0; i-- { // Skip the last byte index[0] to fit the BN254 scalar field.
	// 	hashBin = append(hashBin, api.ToBinary(hashBytes[i].Val, 8)...)
	// }
	// hash := api.FromBinary(hashBin...)
	// api.AssertIsEqual(hash, c.JwtHash)

	// 4. Hash the JWT base64 encoded string and compare it with the expected `JwtHash`.
	sha, err := sha2.New(api)
	if err != nil {
		return err
	}
	sha.Write(packedJwt)
	hashBytes := sha.FixedLengthSum(api.Add(c.JwtHeaderBase64Len, frontend.Variable(1), c.JwtPayloadBase64Len))
	var hashBin []frontend.Variable
	for i := 31; i > 0; i-- { // Skip the last byte to fit the BN254 scalar field.
		api.Println("hashBytes[i].Val", hashBytes[i].Val)
		hashBin = append(hashBin, api.ToBinary(hashBytes[i].Val, 8)...)
	}
	hash := api.FromBinary(hashBin...)
	api.AssertIsEqual(hash, c.JwtHash)

	return nil
}
