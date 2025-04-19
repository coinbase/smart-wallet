package hints

import (
	"bytes"
	"encoding/base64"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// Base64LenHintInputs prepares inputs for the Base64LenHint (this is necessary because gnark hints require frontend.Variable inputs.).
// It sets the inputs as follows:
// - inputs[] is the string bytes as frontend.Variable.
func Base64LenHintInputs(api frontend.API, str []uints.U8) []frontend.Variable {
	inputs := make([]frontend.Variable, len(str))

	for i := range str {
		inputs[i] = str[i].Val
	}

	return inputs
}

// Base64LenHint computes the base64 length of a string.
// The inputs should be formatted as follows:
// - inputs[] is the string bytes as frontend.Variable, possibly padded with null bytes.
// The string is trimmed of trailing null bytes and then encoded to base64 using RawURLEncoding.
// The output is the length of the base64-encoded string.
func Base64LenHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	str := make([]byte, len(inputs))
	for i := range str {
		str[i] = byte(inputs[i].Uint64())
	}

	str = bytes.TrimRight(str, "\x00")

	strBase64 := base64.RawURLEncoding.EncodeToString(str)
	outputs[0].SetUint64(uint64(len(strBase64)))

	return nil
}
