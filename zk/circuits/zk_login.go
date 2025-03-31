package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type ZkLoginCircuit struct {
	// Public inputs
	// JwtHeaderKid    []uints.U8        `gnark:",public"`
	// JwtHeaderKidLen frontend.Variable `gnark:",public"`
	// DerivedHash         frontend.Variable                                 `gnark:",public"`
	// IdpPubkey           ecdsa.PublicKey[emparams.P256Fp, emparams.P256Fr] `gnark:",public"`

	// Private inputs
	JwtBase64    []uints.U8
	JwtBase64Len frontend.Variable
	// JwtSignature ecdsa.Signature[emparams.P256Fr]

	TypOffset, AlgOffset, CrvOffset frontend.Variable
	KidOffset, KidValueLen          frontend.Variable
}

func (c *ZkLoginCircuit) Define(api frontend.API) error {
	// // Hash the JWT base64 encoded string (with the "." separator already included).
	// sha, err := sha2.New(api)
	// if err != nil {
	// 	return err
	// }
	// sha.Write(c.JwtBase64[:])
	// hash := sha.FixedLengthSum(c.JwtBase64Len)
	// var hashBin []frontend.Variable
	// for i := 31; i >= 0; i-- {
	// 	hashBin = append(hashBin, api.ToBinary(hash[i].Val, 8)...)
	// }
	// hashElem := BinaryToEmulatedElement[emulated.P256Fr](api, hashBin)

	// // Verify the ECDSA signature.
	// c.IdpPubkey.Verify(
	// 	api,
	// 	sw_emulated.GetP256Params(),
	// 	hashElem,
	// 	&c.JwtSignature,
	// )

	field, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	decodedJwt := decodeBase64URL(api, field, c.JwtBase64[:])

	ProcessHeader(
		api, field, decodedJwt,
		c.TypOffset, c.AlgOffset, c.CrvOffset,
		c.KidOffset, c.KidValueLen,
	)

	// TODO: Parse the JwtPayload to get the "sub", "iss" and "aud".
	// TODO: Rederive the hash from "sub", "iss" and "aud" and ensure it matches the `DerivedHash`.

	return nil
}
