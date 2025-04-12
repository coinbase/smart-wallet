package hints

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func MaskHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	offset := int(inputs[0].Uint64())
	length := int(inputs[1].Uint64())

	fmt.Printf("offset: %v, length: %v\n", offset, length)

	for i := range offset {
		outputs[i].SetUint64(0)
	}

	for i := offset; i < offset+length; i++ {
		outputs[i].SetUint64(1)
	}

	for i := offset + length; i < len(outputs); i++ {
		outputs[i].SetUint64(0)
	}

	return nil
}

// TODO: Ensure the verification is sufficient.
func VerifyMasks(api frontend.API, expectedSums []frontend.Variable, masks ...[]frontend.Variable) {
	maskCount := len(masks)
	maskLength := len(masks[0])

	for _, mask := range masks[1:] {
		if len(mask) != maskLength {
			panic("masks must be the same length")
		}
	}

	// Tracks the sum of bits in each mask (e.g, maskSums[0] = expectedSums[0], maskSums[1] = expectedSums[1], etc.)
	maskSums := make([]frontend.Variable, maskCount)
	for i := range maskSums {
		maskSums[i] = 0
	}

	// Tracks the sum of all masks.
	combinedSum := make([]frontend.Variable, maskLength)
	for i := range combinedSum {
		combinedSum[i] = 0
	}

	for i, mask := range masks {
		for j, bit := range mask {
			api.AssertIsBoolean(bit)

			maskSums[i] = api.Add(maskSums[i], bit)
			combinedSum[j] = api.Add(combinedSum[j], bit)
		}
	}

	// Ensure maskSums[0] == expectedSums[0], maskSums[1] == expectedSums[1], etc.
	for i, sum := range maskSums {
		api.AssertIsEqual(sum, expectedSums[i])
	}

	// Ensure combinedSum[0] == 0|1, combinedSum[1] == 0|1, etc.
	for _, sum := range combinedSum {
		api.AssertIsBoolean(sum)
	}

}
