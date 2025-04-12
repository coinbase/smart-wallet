package utils

import (
	"github.com/consensys/gnark/frontend"
)

func Equal(api frontend.API, a frontend.Variable, b frontend.Variable) frontend.Variable {
	return api.IsZero(api.Sub(a, b))
}

func Not(api frontend.API, a frontend.Variable) frontend.Variable {
	return api.Sub(1, a)
}
