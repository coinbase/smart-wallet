package utils

import (
	"fmt"
	"math/big"
)

func BytesTo31Chunks(bytes []byte) ([]*big.Int, error) {
	if bytes == nil {
		return nil, fmt.Errorf("input bytes cannot be nil")
	}

	l := len(bytes)
	count := l / 31
	ceilCount := (l + 30) / 31

	variables := make([]*big.Int, ceilCount)
	for i := range count {
		variables[i] = new(big.Int).SetBytes(bytes[i*31 : (i+1)*31])
	}

	if l%31 != 0 {
		variables[count] = new(big.Int).SetBytes(bytes[count*31:])
	}

	return variables, nil
}
