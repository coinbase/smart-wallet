package rsa

import "math/big"

type Mod1e2048 struct{}

func (Mod1e2048) NbLimbs() uint     { return 32 }
func (Mod1e2048) BitsPerLimb() uint { return 64 }
func (Mod1e2048) IsPrime() bool     { return false }
func (Mod1e2048) Modulus() *big.Int {
	val, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	return val
}
