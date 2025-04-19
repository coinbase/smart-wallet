package hints

import (
	"math/big"
	"strings"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

// OffsetHintInputs prepares inputs for the OffsetHint.
// It sets the inputs as follows:
// - The inputs[0] is the length of the needle.
// - The inputs[1:1+len(needle)] is the needle.
// - The inputs[1+len(needle):] is the haystack bytes as frontend.Variable.
func OffsetHintInputs(api frontend.API, needle string, haystack []uints.U8) []frontend.Variable {
	inputs := make([]frontend.Variable, 1+len(needle)+len(haystack))
	inputs[0] = len(needle)
	for i := range needle {
		inputs[1+i] = needle[i]
	}
	for i := range haystack {
		inputs[1+len(needle)+i] = haystack[i].Val
	}

	return inputs
}

// OffsetHint computes the offset of the needle in the haystack.
// Inputs should be formatted as follows:
// - inputs[0] is the length of the needle.
// - inputs[1:1+len(needle)] is the needle.
// - inputs[1+len(needle):] is the haystack bytes as frontend.Variable.
// The output is the offset of the needle in the haystack.
func OffsetHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	needleLen := int(inputs[0].Uint64())

	needle := make([]byte, needleLen)
	for i := range needle {
		needle[i] = byte(inputs[1+i].Uint64())
	}
	needleStr := string(needle)

	input := make([]byte, len(inputs)-1-needleLen)
	for i := range input {
		input[i] = byte(inputs[1+needleLen+i].Uint64())
	}
	inputStr := string(input)

	offset := strings.Index(inputStr, needleStr)
	outputs[0].SetUint64(uint64(offset))

	return nil
}
