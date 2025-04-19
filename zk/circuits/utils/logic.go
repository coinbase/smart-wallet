package utils

import (
	"github.com/consensys/gnark/frontend"
)

// Equal returns 1 if a == b, 0 otherwise.
func Equal(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

// Not returns 1 if a == 0, 0 otherwise.
func Not(api frontend.API, a frontend.Variable) frontend.Variable {
	return api.Sub(1, a)
}
