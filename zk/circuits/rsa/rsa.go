package rsa

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

// Hardcoded DER prefix for SHA-256 with RSASSA-PKCS1-v1_5
var Sha256DerPrefixBytes = [19]frontend.Variable{
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
}

func VerifyRSASignature[T emulated.FieldParams](api frontend.API, hash []frontend.Variable, signature, idpPublicKeyN *emulated.Element[T]) error {
	f, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}

	// TODO: Do I need to check signature is in [0, n-1]?
	// TODO: Do I need to check n.length >= 11 + SHA256_DER_PREFIX.length + 32?

	em := rsaModExp(f, signature, idpPublicKeyN)
	emBytes := toBytes(api, f, em)

	// Verify the PKCS#1 v1.5 header.
	api.AssertIsEqual(emBytes[0], 0x00)
	api.AssertIsEqual(emBytes[1], 0x01)

	var fp T
	pkLength := int(fp.NbLimbs() * fp.BitsPerLimb() / 8)
	paddingLength := pkLength - 2 - 1 - len(Sha256DerPrefixBytes) - 32

	// Verify the PKCS#1 v1.5 padding.
	offset := 2
	for range paddingLength {
		api.AssertIsEqual(emBytes[offset], 0xff)
		offset++
	}

	// Verify the 0x00 delimiter after padding.
	api.AssertIsEqual(emBytes[offset], 0x00)
	offset++

	// Verify the DER-encoded SHA-256 prefix.
	for _, b := range Sha256DerPrefixBytes {
		api.AssertIsEqual(emBytes[offset], b)
		offset++
	}

	// Verify the SHA-256 hash.
	for _, b := range hash {
		api.AssertIsEqual(emBytes[offset], b)
		offset++
	}

	return nil
}

func rsaModExp[T emulated.FieldParams](f *emulated.Field[T], base, modulus *emulated.Element[T]) *emulated.Element[T] {
	// Hardcode the exponent to be 65537
	acc := base
	for range 16 {
		acc = f.ModMul(acc, acc, modulus)
	}
	acc = f.ModMul(acc, base, modulus)

	return acc
}

// TODO: Should be replaced by a ToByteHint instead of using ToBitsCanonical to improve performance.
func toBytes[T emulated.FieldParams](api frontend.API, f *emulated.Field[T], value *emulated.Element[T]) []frontend.Variable {
	bits := f.ToBits(value)

	nbBytes := len(bits) / 8
	bytes := make([]frontend.Variable, 0, nbBytes)
	for i := nbBytes - 1; i >= 0; i-- {
		var b frontend.Variable = 0
		for j := range 8 {
			b = api.Add(b, api.Mul(bits[i*8+j], 1<<j))
		}
		bytes = append(bytes, b)
	}

	return bytes
}
