package main

import (
	"github.com/coinbase/smart-wallet/circuits/circuits"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
)

func main() {
	zkCircuit := circuits.ZkLoginCircuit{
		JwtBase64: make([]uints.U8, circuits.MaxJwtLen),
	}
	_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &zkCircuit)
	if err != nil {
		panic(err)
	}

}
