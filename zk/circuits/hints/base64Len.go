package hints

import (
	"bytes"
	"encoding/base64"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func Base64LenHintInputs(api frontend.API, json []uints.U8) []frontend.Variable {
	inputs := make([]frontend.Variable, len(json))

	for i := range json {
		inputs[i] = json[i].Val
	}

	return inputs
}

func Base64LenHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	jsonStr := make([]byte, len(inputs))
	for i := range jsonStr {
		jsonStr[i] = byte(inputs[i].Uint64())
	}

	jsonStr = bytes.TrimRight(jsonStr, "\x00")

	jsonBase64 := base64.RawURLEncoding.EncodeToString(jsonStr)
	outputs[0].SetUint64(uint64(len(jsonBase64)))

	return nil
}
