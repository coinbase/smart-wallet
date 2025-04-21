package utils

import (
	"fmt"
	"math/big"
)

func BytesToElements(bytes []byte, elementSize int) ([]*big.Int, error) {
	if bytes == nil {
		return nil, fmt.Errorf("input bytes cannot be nil")
	}

	l := len(bytes)
	count := l / elementSize
	ceilCount := (l + elementSize - 1) / elementSize

	elements := make([]*big.Int, ceilCount)
	for i := range count {
		elements[i] = new(big.Int).SetBytes(bytes[i*elementSize : (i+1)*elementSize])
	}

	if l%elementSize != 0 {
		elements[count] = new(big.Int).SetBytes(bytes[count*elementSize:])
	}

	return elements, nil
}
