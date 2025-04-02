package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"
)

type ZkLoginCircuit struct {
	// Public inputs
	JwtHeaderKidValue    []uints.U8        `gnark:",public"`
	DerivedHash          frontend.Variable `gnark:",public"`
	JwtHash              frontend.Variable `gnark:",public"`
	JwtPayloadNonceValue []uints.U8        `gnark:",public"`

	// Private inputs
	JwtHeader           []uints.U8
	JwtHeaderBase64Len  frontend.Variable
	JwtPayload          []uints.U8
	JwtPayloadBase64Len frontend.Variable

	TypOffset, AlgOffset   frontend.Variable
	KidOffset, KidValueLen frontend.Variable

	IssOffset, IssValueLen     frontend.Variable
	AudOffset, AudValueLen     frontend.Variable
	SubOffset, SubValueLen     frontend.Variable
	NonceOffset, NonceValueLen frontend.Variable
}

func (c *ZkLoginCircuit) Define(api frontend.API) error {
	field, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}

	// 1. Encode the JWT header and payload to base64.
	base64Encoder := NewBase64Encoder(api, field)
	encodedJwtHeader := base64Encoder.EncodeBase64URL(c.JwtHeader)
	encodedJwtPayload := base64Encoder.EncodeBase64URL(c.JwtPayload)

	// 2. Recompute the JWT hash and compare it with the expected `JwtHash`.
	packedJwt := c.packJwt(api, field, encodedJwtHeader, encodedJwtPayload)
	jwtHash := c.jwtHash(api, packedJwt)
	api.AssertIsEqual(jwtHash, c.JwtHash)

	// 3. Verify the JWT content and extract the "iss", "aud" and "sub" fields.
	jwtVerifier := NewJwtVerifier(api, field)
	jwtVerifier.ProcessJwtHeader(
		c.JwtHeader,
		c.JwtHeaderKidValue,
		c.TypOffset, c.AlgOffset,
		c.KidOffset, c.KidValueLen,
	)

	iss, aud, sub := jwtVerifier.ProcessJwtPayload(
		c.JwtPayload,
		c.JwtPayloadNonceValue,
		c.IssOffset, c.IssValueLen,
		c.AudOffset, c.AudValueLen,
		c.SubOffset, c.SubValueLen,
		c.NonceOffset, c.NonceValueLen,
	)

	// 4. Recompute the derived hash and compare it with the expected `DerivedHash`.
	derivedHash := c.deriveHash(api, iss[:], aud[:], sub[:])
	api.AssertIsEqual(derivedHash, c.DerivedHash)

	return nil
}

func (c *ZkLoginCircuit) deriveHash(
	api frontend.API,
	iss []uints.U8,
	aud []uints.U8,
	sub []uints.U8,
) (derivedHash frontend.Variable) {
	sha, err := sha2.New(api)
	if err != nil {
		return err
	}

	sha.Write(iss[:])
	sha.Write(aud[:])
	sha.Write(sub[:])
	hashBytes := sha.Sum()
	var hashBin []frontend.Variable
	for i := 31; i > 0; i-- { // Skip the last byte index[0] to fit the BN254 scalar field.
		hashBin = append(hashBin, api.ToBinary(hashBytes[i].Val, 8)...)
	}
	derivedHash = api.FromBinary(hashBin...)
	return derivedHash
}

func (c *ZkLoginCircuit) packJwt(
	api frontend.API,
	field *uints.BinaryField[uints.U32],
	header []uints.U8,
	payload []uints.U8,
) (packedJwt []uints.U8) {
	packedJwt = make([]uints.U8, MaxJwtLenBase64)
	for i := range packedJwt {
		packedJwt[i] = uints.NewU8(0)
	}
	copy(packedJwt, header)

	// Lookup table: <payload>
	lookup := logderivlookup.New(api)
	for _, b := range payload {
		lookup.Insert(b.Val)
	}

	startPayloadIndex := api.Add(c.JwtHeaderBase64Len, 1)
	endPayloadIndex := api.Add(startPayloadIndex, c.JwtPayloadBase64Len)

	for i := range MaxJwtLenBase64 {
		isHeader := lessThan(api, 16, i, c.JwtHeaderBase64Len)
		isDot := equal(api, i, c.JwtHeaderBase64Len)
		isPayload := api.Mul(
			not(api, lessThan(api, 16, i, startPayloadIndex)),
			lessThan(api, 16, i, endPayloadIndex),
		)

		payloadByte := lookup.Lookup(
			api.Mul(isPayload, api.Sub(i, startPayloadIndex)),
		)[0]

		b := api.Add(
			api.Mul(isHeader, packedJwt[i].Val),
			api.Mul(isDot, '.'),
			api.Mul(isPayload, payloadByte),
		)
		packedJwt[i] = field.ByteValueOf(b)
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
