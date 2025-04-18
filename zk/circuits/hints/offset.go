package hints

import (
	"math/big"
	"strings"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func OffsetHintInputs(api frontend.API, niddle string, json []uints.U8) []frontend.Variable {
	inputs := make([]frontend.Variable, 1+len(niddle)+len(json))
	inputs[0] = len(niddle)
	for i := range niddle {
		inputs[1+i] = niddle[i]
	}
	for i := range json {
		inputs[1+len(niddle)+i] = json[i].Val
	}

	return inputs
}

func OffsetHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	niddleLen := int(inputs[0].Uint64())

	niddle := make([]byte, niddleLen)
	for i := range niddle {
		niddle[i] = byte(inputs[1+i].Uint64())
	}
	niddleStr := string(niddle)

	input := make([]byte, len(inputs)-1-niddleLen)
	for i := range input {
		input[i] = byte(inputs[1+niddleLen+i].Uint64())
	}
	inputStr := string(input)

	offset := strings.Index(inputStr, niddleStr)
	outputs[0].SetUint64(uint64(offset))

	return nil
}
