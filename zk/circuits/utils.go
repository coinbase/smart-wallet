package circuits

import "github.com/consensys/gnark/frontend"

func equal(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

func lessThan(api frontend.API, bitLen int, a frontend.Variable, b frontend.Variable) frontend.Variable {
	// Do res = 1<<bitLen + (a-b) and checks if the res[bitLen] is set.
	n := api.Sub(api.Add(a, 1<<bitLen), b)
	bin := api.ToBinary(n, bitLen+1)

	// If a >= b then bin[bitLen] will still be set.
	isAboveOrEqual := bin[bitLen]

	// 1 if a < b, 0 otherwise.
	return api.Sub(1, isAboveOrEqual)
}

func not(api frontend.API, a frontend.Variable) frontend.Variable {
	return api.Sub(1, a)
}
