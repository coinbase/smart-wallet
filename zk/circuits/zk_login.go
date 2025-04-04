package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

type ZkLoginCircuit struct {
	// Public inputs.
	JwtHeaderBase64 []uints.U8        `gnark:",public"`
	Nonce           []uints.U8        `gnark:",public"`
	JwtHash         frontend.Variable `gnark:",public"`
	ZkAddr          frontend.Variable `gnark:",public"`

	// Semi-private inputs (to not require the verifier to provide them).
	JwtHeaderBase64Len    frontend.Variable
	NonceOffset, NonceLen frontend.Variable

	// Private inputs.
	JwtPayloadJson      []uints.U8
	JwtPayloadBase64Len frontend.Variable

	IssOffset, IssLen frontend.Variable
	AudOffset, AudLen frontend.Variable
	SubOffset, SubLen frontend.Variable

	UserSalt []uints.U8
}

func (c *ZkLoginCircuit) Define(api frontend.API) error {
	// 1. Encode the JWT header and payload to base64.
	base64Encoder := NewBase64Encoder(api)
	jwtPayloadBase64 := base64Encoder.EncodeBase64URL(c.JwtPayloadJson)

	// 2. Recompute the JWT hash and compare it with the expected `JwtHash`.
	packedJwt := c.packJwt(api, c.JwtHeaderBase64, jwtPayloadBase64)
	jwtHash := c.jwtHash(api, packedJwt)
	api.AssertIsEqual(jwtHash, c.JwtHash)

	// 3. Verify the JWT content and extract the "iss", "aud" and "sub" fields.
	//    NOTE: The JWT header is provided as public input and thus MUST be validated by the verifier.
	jwtVerifier := NewJwtVerifier(api)
	iss, aud, sub := jwtVerifier.ProcessJwtPayload(
		c.JwtPayloadJson,
		c.Nonce,
		c.IssOffset, c.IssLen,
		c.AudOffset, c.AudLen,
		c.SubOffset, c.SubLen,
		c.NonceOffset, c.NonceLen,
	)

	// 4. Recompute the zkAddr and compare it with the expected `ZkAddr`.
	zkAddr := c.zkAddr(api, iss, aud, sub, c.UserSalt)
	api.AssertIsEqual(zkAddr, c.ZkAddr)

	return nil
}

func (c *ZkLoginCircuit) zkAddr(
	api frontend.API,
	iss, aud, sub []uints.U8,
	userSalt []uints.U8,
) (zkAddr frontend.Variable) {
	sha, err := sha2.New(api)
	if err != nil {
		return err
	}

	sha.Write(iss)
	sha.Write(aud)
	sha.Write(sub)
	sha.Write(userSalt)
	hashBytes := sha.Sum()
	var hashBin []frontend.Variable
	for i := 31; i > 0; i-- { // Skip the last byte index[0] to fit the BN254 scalar field.
		hashBin = append(hashBin, api.ToBinary(hashBytes[i].Val, 8)...)
	}
	zkAddr = api.FromBinary(hashBin...)
	return zkAddr
}

func (c *ZkLoginCircuit) packJwt(
	api frontend.API,
	headerBase64 []uints.U8,
	payloadBase64 []uints.U8,
) (packedJwt []uints.U8) {
	packedJwt = make([]uints.U8, MaxJwtLenBase64)
	for i := range packedJwt {
		packedJwt[i] = uints.NewU8(0)
	}
	copy(packedJwt, headerBase64)

	// Lookup table (size = MaxJwtLenBase64): <payload> + <padding>
	lookup := logderivlookup.New(api)
	for _, b := range payloadBase64 {
		lookup.Insert(b.Val)
	}
	for range MaxJwtLenBase64 - len(payloadBase64) {
		lookup.Insert(0)
	}

	startPayloadIndex := api.Add(c.JwtHeaderBase64Len, 1)

	for i := range MaxJwtLenBase64 {
		isDot := equal(api, i, c.JwtHeaderBase64Len)
		isPayload := not(api, lessThan(api, 11, i, startPayloadIndex))
		isHeader := api.Mul(
			not(api, isDot),
			not(api, isPayload),
		)

		payloadByte := lookup.Lookup(
			api.Mul(isPayload, api.Sub(i, startPayloadIndex)),
		)[0]

		b := api.Add(
			api.Mul(isHeader, packedJwt[i].Val),
			api.Mul(isDot, '.'),
			api.Mul(isPayload, payloadByte),
		)
		packedJwt[i] = uints.U8{Val: b}
	}

	return packedJwt
}

func (c *ZkLoginCircuit) jwtHash(
	api frontend.API,
	packedJwt []uints.U8,
) (jwtHash frontend.Variable) {
	sha, err := sha2.New(api)
	if err != nil {
		return err
	}
	sha.Write(packedJwt)
	hashBytes := sha.FixedLengthSum(api.Add(c.JwtHeaderBase64Len, frontend.Variable(1), c.JwtPayloadBase64Len))
	var hashBin []frontend.Variable
	for i := 31; i > 0; i-- { // Skip the last byte to fit the BN254 scalar field.
		hashBin = append(hashBin, api.ToBinary(hashBytes[i].Val, 8)...)
	}
	jwtHash = api.FromBinary(hashBin...)
	return jwtHash
}
