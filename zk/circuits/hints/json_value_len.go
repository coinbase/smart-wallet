package hints

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// JsonValueLenHintInputs prepares inputs for the JsonValueLenHint.
// It sets the inputs as follows:
// - inputs[0] is the length of the key.
// - inputs[1:1+len(key)] is the key.
// - inputs[1+len(key):] is the JSON string bytes as frontend.Variable, possibly padded with null bytes.
func JsonValueLenHintInputs(api frontend.API, key string, json []uints.U8) []frontend.Variable {
	inputs := make([]frontend.Variable, 1+len(key)+len(json))
	inputs[0] = len(key)
	for i := range key {
		inputs[1+i] = key[i]
	}
	for i := range json {
		inputs[1+len(key)+i] = json[i].Val
	}

	return inputs
}

// JsonValueLenHint computes the length of the value (including the potential surrounding quotes) for a key in a JSON object.
// The inputs should be formatted as follows:
// - inputs[0] is the length of the key.
// - inputs[1:1+len(key)] is the key.
// - inputs[1+len(key):] is the JSON string bytes as frontend.Variable, possibly padded with null bytes.
func JsonValueLenHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	keyLen := int(inputs[0].Uint64())

	key := make([]byte, keyLen)
	for i := range key {
		key[i] = byte(inputs[1+i].Uint64())
	}
	keyStr := string(key)

	jsonStr := make([]byte, len(inputs)-1-keyLen)
	for i := range jsonStr {
		jsonStr[i] = byte(inputs[1+keyLen+i].Uint64())
	}
	jsonStr = bytes.TrimRight(jsonStr, "\x00")

	// parse JSON inputStr and get the value of keyStr
	var rawMessage map[string]json.RawMessage
	if err := json.Unmarshal(jsonStr, &rawMessage); err != nil {
		return fmt.Errorf("failed to parse JSON payload: %w", err)
	}

	value, ok := rawMessage[keyStr]
	if !ok {
		return fmt.Errorf("key not found in JSON payload: %s", keyStr)
	}

	outputs[0].SetUint64(uint64(len(value)))

	return nil
}
