package jwt

import (
	"github.com/coinbase/smart-wallet/circuits/circuits/v2/hints"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

func jwtHeaderOffsetsFromHints(api frontend.API, json []uints.U8) (typOffset, algOffset, kidOffset frontend.Variable, err error) {
	inputs := hints.OffsetHintInputs(api, TypJson, json)
	typOffset_, err := api.Compiler().NewHint(hints.OffsetHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, err
	}
	typOffset = typOffset_[0]

	inputs = hints.OffsetHintInputs(api, AlgJson, json)
	algOffset_, err := api.Compiler().NewHint(hints.OffsetHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, err
	}
	algOffset = algOffset_[0]

	inputs = hints.OffsetHintInputs(api, KidJsonPrefix, json)
	kidOffset_, err := api.Compiler().NewHint(hints.OffsetHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, err
	}
	kidOffset = kidOffset_[0]

	return
}

func jwtHeaderValueLengthsFromHints(api frontend.API, json []uints.U8) (kidValueLen frontend.Variable, err error) {
	inputs := hints.ValueLenHintInputs(api, KidJsonKey, json)
	kidValueLen_, err := api.Compiler().NewHint(hints.ValueLenHint, 1, inputs...)
	if err != nil {
		return 0, err
	}
	kidValueLen = kidValueLen_[0]

	return
}

func jwtPayloadOffsetsFromHints(api frontend.API, json []uints.U8) (issOffset, audOffset, subOffset frontend.Variable, err error) {
	inputs := hints.OffsetHintInputs(api, IssJsonPrefix, json)
	issOffset_, err := api.Compiler().NewHint(hints.OffsetHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, err
	}
	issOffset = issOffset_[0]

	inputs = hints.OffsetHintInputs(api, AudJsonPrefix, json)
	audOffset_, err := api.Compiler().NewHint(hints.OffsetHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, err
	}
	audOffset = audOffset_[0]

	inputs = hints.OffsetHintInputs(api, SubJsonPrefix, json)
	subOffset_, err := api.Compiler().NewHint(hints.OffsetHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, err
	}
	subOffset = subOffset_[0]

	return
}

func jwtPayloadValueLengthsFromHints(api frontend.API, json []uints.U8) (issValueLen, audValueLen, subValueLen frontend.Variable, err error) {
	inputs := hints.ValueLenHintInputs(api, IssJsonKey, json)
	issValueLen_, err := api.Compiler().NewHint(hints.ValueLenHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, err
	}
	issValueLen = issValueLen_[0]

	inputs = hints.ValueLenHintInputs(api, AudJsonKey, json)
	audValueLen_, err := api.Compiler().NewHint(hints.ValueLenHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, err
	}
	audValueLen = audValueLen_[0]

	inputs = hints.ValueLenHintInputs(api, SubJsonKey, json)
	subValueLen_, err := api.Compiler().NewHint(hints.ValueLenHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, err
	}
	subValueLen = subValueLen_[0]

	return
}

func jwtHeaderMasksFromHints(
	api frontend.API,
	typOffset, algOffset, kidOffset, kidValueLen frontend.Variable,
) (typMask, algMask, kidMask []frontend.Variable, err error) {
	typLen := len(TypJson)
	typMask, err = api.Compiler().NewHint(hints.MaskHint, MaxHeaderJsonLen, typOffset, typLen)
	if err != nil {
		return nil, nil, nil, err
	}

	algLen := len(AlgJson)
	algMask, err = api.Compiler().NewHint(hints.MaskHint, MaxHeaderJsonLen, algOffset, algLen)
	if err != nil {
		return nil, nil, nil, err
	}

	kidLen := api.Add(len(KidJsonPrefix), kidValueLen)
	kidMask, err = api.Compiler().NewHint(hints.MaskHint, MaxHeaderJsonLen, kidOffset, kidLen)
	if err != nil {
		return nil, nil, nil, err
	}

	expectedSums := []frontend.Variable{typLen, algLen, kidLen}
	hints.VerifyMasks(api, expectedSums, typMask, algMask, kidMask)

	return
}

func jwtPayloadMasksFromHints(
	api frontend.API,
	issOffset, issValueLen, audOffset, audValueLen, subOffset, subValueLen frontend.Variable,
) (issMask, audMask, subMask []frontend.Variable, err error) {
	issLen := api.Add(len(IssJsonPrefix), issValueLen)
	issMask, err = api.Compiler().NewHint(hints.MaskHint, MaxPayloadJsonLen, issOffset, issLen)
	if err != nil {
		return nil, nil, nil, err
	}

	audLen := api.Add(len(AudJsonPrefix), audValueLen)
	audMask, err = api.Compiler().NewHint(hints.MaskHint, MaxPayloadJsonLen, audOffset, audLen)
	if err != nil {
		return nil, nil, nil, err
	}

	subLen := api.Add(len(SubJsonPrefix), subValueLen)
	subMask, err = api.Compiler().NewHint(hints.MaskHint, MaxPayloadJsonLen, subOffset, subLen)
	if err != nil {
		return nil, nil, nil, err
	}

	expectedSums := []frontend.Variable{issLen, audLen, subLen}
	hints.VerifyMasks(api, expectedSums, issMask, audMask, subMask)

	return
}
