package hints

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
)

func NonceHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	nonce := inputs[0]

	bytes := nonce.Bytes()
	for i := range bytes {
		outputs[i].SetUint64(uint64(bytes[i]))
	}

	return nil
}

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
