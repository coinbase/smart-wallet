package hints

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// NonceHint converts a big.Int nonce into a slice of big.Int outputs, each representing a byte of the nonce.
// The inputs should be formatted as follows:
// - inputs[0] is the nonce.
func NonceHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	nonce := inputs[0]

	bytes := nonce.Bytes()
	for i := range bytes {
		outputs[i].SetUint64(uint64(bytes[i]))
	}

	return nil
}

// VerifyNonce verifies that the nonce bytes decomposition is correct by ensuring
// that reconstructing the nonce from its byte representation matches the original nonce.
func VerifyNonce(api frontend.API, nonceBytes []frontend.Variable, nonce frontend.Variable) {
	sum := frontend.Variable(0)
	factor := frontend.Variable(1)
	for i := len(nonceBytes) - 1; i >= 0; i-- {
		b := nonceBytes[i]
		v := api.Mul(b, factor)
		sum = api.Add(sum, v)
		factor = api.Mul(factor, 256)
	}

	api.AssertIsEqual(sum, nonce)
}
