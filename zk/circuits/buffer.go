package circuits

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

type Buffer struct {
	api   frontend.API
	field *uints.BinaryField[uints.U64]
	data  []uints.U8
	len   frontend.Variable
	min   int
	max   int
}

func NewBuffer(api frontend.API, cap int) (*Buffer, error) {
	field, err := uints.New[uints.U64](api)
	if err != nil {
		return nil, fmt.Errorf("new binary field: %w", err)
	}
	data := make([]uints.U8, cap)
	for i := range data {
		data[i] = uints.NewU8(0)
	}
	return &Buffer{
		api:   api,
		field: field,
		data:  data,
		len:   0,
		min:   0,
		max:   1,
	}, nil
}

func (b *Buffer) AppendByte(v uints.U8) {
	for i := b.min; i < min(b.max, len(b.data)); i++ {
		b.data[i].Val = b.api.Add(b.data[i].Val, b.api.Mul(v.Val, b.api.IsZero(b.api.Sub(b.len, i))))
	}
	b.min++
	b.max++
	b.len = b.api.Add(b.len, 1)
}

func (b *Buffer) AppendBinary(v frontend.Variable, n int) {
	bin := b.api.ToBinary(v, n*8)
	for i := 0; i < n; i++ {
		b.AppendByte(b.field.ByteValueOf(b.api.FromBinary(bin[i*8 : (i+1)*8]...)))
	}
}

func (b *Buffer) AppendFixed(v []uints.U8) {
	for _, e := range v {
		b.AppendByte(e)
	}
}

func (b *Buffer) AppendVariable(v []uints.U8, l frontend.Variable) {
	cond := frontend.Variable(1)
	for i, e := range v {
		cond = b.api.Mul(cond, b.api.Sub(1, b.api.IsZero(b.api.Sub(l, i))))
		b.maybeAppendByte(e, cond)
	}
}

func (b *Buffer) MaybeAppendByte(v uints.U8, cond frontend.Variable) {
	b.api.AssertIsBoolean(cond)
	b.maybeAppendByte(v, cond)
}

func (b *Buffer) MaybeAppendBinary(v frontend.Variable, n int, cond frontend.Variable) {
	b.api.AssertIsBoolean(cond)
	bin := b.api.ToBinary(v, n*8)
	for i := 0; i < n; i++ {
		b.maybeAppendByte(b.field.ByteValueOf(b.api.FromBinary(bin[i*8:(i+1)*8]...)), cond)
	}
}

func (b *Buffer) MaybeAppendFixed(v []uints.U8, cond frontend.Variable) {
	b.api.AssertIsBoolean(cond)
	for _, e := range v {
		b.maybeAppendByte(e, cond)
	}
}

func (b *Buffer) MaybeAppendVariable(v []uints.U8, l frontend.Variable, cond frontend.Variable) {
	b.api.AssertIsBoolean(cond)
	for i, e := range v {
		cond = b.api.Mul(cond, b.api.Sub(1, b.api.IsZero(b.api.Sub(l, i))))
		b.maybeAppendByte(e, cond)
	}
}

func (b *Buffer) maybeAppendByte(v uints.U8, cond frontend.Variable) {
	for i := b.min; i < min(b.max, len(b.data)); i++ {
		b.data[i].Val = b.api.Add(b.data[i].Val, b.api.Mul(v.Val, b.api.IsZero(b.api.Sub(b.len, i)), cond))
	}
	b.max++
	b.len = b.api.Add(b.len, cond)
}
