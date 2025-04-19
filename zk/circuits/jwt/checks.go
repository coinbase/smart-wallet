package jwt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/coinbase/smart-wallet/circuits/circuits/utils"
)

// verifyByte validates that a byte at position i in the JSON matches the expected value.
// When mask is 1, the check is active; when mask is 0, the check is skipped.
func verifyByte(
	api frontend.API,
	json []uints.U8,
	lookup *logderivlookup.Table,
	i int,
	mask frontend.Variable,
	startOffset frontend.Variable,
) {
	// Get the byte from the JWT JSON.
	b := json[i].Val

	// Get the corresponding expected byte from the lookup table.
	expectedByte := lookup.Lookup(
		api.Mul(
			mask,
			api.Sub(i, startOffset), // NOTE: It is fine to underflow here.
		),
	)[0]

	// assert(mask == 0 || b == expectedByte)
	api.AssertIsDifferent(
		0,
		api.Add(
			utils.Equal(api, mask, 0),
			utils.Equal(api, b, expectedByte),
		),
	)
}

// verifySeparator validates that the byte at position i is a separator (comma or close brace)
// when i equals the end offset. The check is only active when i == end.
func verifySeparator(
	api frontend.API,
	json []uints.U8,
	i int,
	end frontend.Variable,
) {
	// Get the byte from the JWT JSON.
	b := json[i].Val

	// i == end
	shouldBeSeparator := utils.Equal(api, i, end)

	// assert(shouldBeSeparator == 0 || (b == commaU8 || b == closeBraceU8))
	api.AssertIsDifferent(
		0,
		api.Add(
			utils.Equal(api, shouldBeSeparator, 0),
			api.Add(
				utils.Equal(api, b, commaU8.Val),
				utils.Equal(api, b, closeBraceU8.Val),
			),
		),
	)
}
