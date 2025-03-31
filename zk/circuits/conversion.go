package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

func ToEmulatedElement[F emulated.FieldParams](api frontend.API, v frontend.Variable) *emulated.Element[F] {
	var fr F
	binary := api.ToBinary(v, int(fr.NbLimbs()*fr.BitsPerLimb()))
	return BinaryToEmulatedElement[F](api, binary)
}

func BinaryToEmulatedElement[F emulated.FieldParams](api frontend.API, binary []frontend.Variable) *emulated.Element[F] {
	var fr F
	limbs := make([]frontend.Variable, fr.NbLimbs())
	bitsPerLimb := int(fr.BitsPerLimb())

	// Round up to the nearest limb size
	limbsCount := (len(binary) + bitsPerLimb - 1) / bitsPerLimb

	// Fill all the limbs expect the last one (which might be smaller)
	for i := range limbsCount - 1 {
		limbs[i] = api.FromBinary(binary[i*bitsPerLimb : (i+1)*bitsPerLimb]...)
	}

	// Fill the last limb (which might be smaller)
	limbs[limbsCount-1] = api.FromBinary(binary[(limbsCount-1)*bitsPerLimb:]...)

	// Fill the rest of the limbs with zeros
	for i := limbsCount; i < len(limbs); i++ {
		limbs[i] = 0
	}

	return &emulated.Element[F]{Limbs: limbs[:]}
}
