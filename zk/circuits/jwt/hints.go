package jwt

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"

	"github.com/coinbase/smart-wallet/circuits/circuits/hints"
)

// sectionBase64LenghtsFromHints calculates the length of the base64-encoded JWT header and payload sections.
// It returns the length of each section as frontend.Variable values.
func sectionBase64LenghtsFromHints(
	api frontend.API,
	headerJson, payloadJson []uints.U8,
) (headerBase64Len, payloadBase64Len frontend.Variable, err error) {
	inputs := hints.Base64LenHintInputs(api, headerJson)
	headerBase64Len_, err := api.Compiler().NewHint(hints.Base64LenHint, 1, inputs...)
	if err != nil {
		return 0, 0, err
	}
	headerBase64Len = headerBase64Len_[0]

	inputs = hints.Base64LenHintInputs(api, payloadJson)
	payloadBase64Len_, err := api.Compiler().NewHint(hints.Base64LenHint, 1, inputs...)
	if err != nil {
		return 0, 0, err
	}
	payloadBase64Len = payloadBase64Len_[0]

	return
}

// sectionBase64MasksFromHints calculates the masks for the base64-encoded JWT header and payload sections.
// It returns the mask for the header, the dot mask, and the mask for the payload.
func sectionBase64MasksFromHints(
	api frontend.API,
	headerBase64Len, payloadBase64Len frontend.Variable,
) (headerBase64Mask, dotMask, payloadBase64Mask []frontend.Variable, err error) {
	headerBase64Mask, err = api.Compiler().NewHint(hints.ContiguousMaskHint, MaxLenBase64, 0, headerBase64Len)
	if err != nil {
		return nil, nil, nil, err
	}

	dotMask, err = api.Compiler().NewHint(hints.ContiguousMaskHint, MaxLenBase64, headerBase64Len, 1)
	if err != nil {
		return nil, nil, nil, err
	}

	payloadOffset := api.Add(headerBase64Len, 1)
	payloadBase64Mask, err = api.Compiler().NewHint(hints.ContiguousMaskHint, MaxLenBase64, payloadOffset, payloadBase64Len)
	if err != nil {
		return nil, nil, nil, err
	}

	expectedSums := []frontend.Variable{headerBase64Len, 1, payloadBase64Len}
	hints.VerifyMasks(api, expectedSums, headerBase64Mask, dotMask, payloadBase64Mask)

	return
}

// headerOffsetsFromHints calculates the offsets for the JWT header.
// It returns the offset for the typ, the alg, and the kid.
func headerOffsetsFromHints(
	api frontend.API, json []uints.U8,
) (typOffset, algOffset, kidOffset frontend.Variable, err error) {
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

// headerValueLengthsFromHints calculates the length of the kid value.
// It returns the length of the kid value as a frontend.Variable value.
func headerValueLengthsFromHints(
	api frontend.API, json []uints.U8,
) (kidValueLen frontend.Variable, err error) {
	inputs := hints.JsonValueLenHintInputs(api, KidJsonKey, json)
	kidValueLen_, err := api.Compiler().NewHint(hints.JsonValueLenHint, 1, inputs...)
	if err != nil {
		return 0, err
	}
	kidValueLen = kidValueLen_[0]

	return
}

// payloadOffsetsFromHints calculates the offsets for the JWT payload.
// It returns the offset for the iss, the aud, the sub, and the nonce.
func payloadOffsetsFromHints(
	api frontend.API, json []uints.U8,
) (issOffset, audOffset, subOffset, nonceOffset frontend.Variable, err error) {
	inputs := hints.OffsetHintInputs(api, IssJsonPrefix, json)
	issOffset_, err := api.Compiler().NewHint(hints.OffsetHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	issOffset = issOffset_[0]

	inputs = hints.OffsetHintInputs(api, AudJsonPrefix, json)
	audOffset_, err := api.Compiler().NewHint(hints.OffsetHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	audOffset = audOffset_[0]

	inputs = hints.OffsetHintInputs(api, SubJsonPrefix, json)
	subOffset_, err := api.Compiler().NewHint(hints.OffsetHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	subOffset = subOffset_[0]

	inputs = hints.OffsetHintInputs(api, NonceJsonPrefix, json)
	nonceOffset_, err := api.Compiler().NewHint(hints.OffsetHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	nonceOffset = nonceOffset_[0]

	return
}

// payloadValueLengthsFromHints calculates the length of the iss, the aud, the sub, and the nonce values.
// It returns the length of each value as a frontend.Variable value.
func payloadValueLengthsFromHints(
	api frontend.API, json []uints.U8,
) (issValueLen, audValueLen, subValueLen, nonceValueLen frontend.Variable, err error) {
	inputs := hints.JsonValueLenHintInputs(api, IssJsonKey, json)
	issValueLen_, err := api.Compiler().NewHint(hints.JsonValueLenHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	issValueLen = issValueLen_[0]

	inputs = hints.JsonValueLenHintInputs(api, AudJsonKey, json)
	audValueLen_, err := api.Compiler().NewHint(hints.JsonValueLenHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	audValueLen = audValueLen_[0]

	inputs = hints.JsonValueLenHintInputs(api, SubJsonKey, json)
	subValueLen_, err := api.Compiler().NewHint(hints.JsonValueLenHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	subValueLen = subValueLen_[0]

	inputs = hints.JsonValueLenHintInputs(api, NonceJsonKey, json)
	nonceValueLen_, err := api.Compiler().NewHint(hints.JsonValueLenHint, 1, inputs...)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	nonceValueLen = nonceValueLen_[0]

	return
}

// headerMasksFromHints calculates the masks for the JWT header.
// It returns the mask for the typ, the alg, and the kid.
func headerMasksFromHints(
	api frontend.API,
	typOffset, algOffset, kidOffset, kidValueLen frontend.Variable,
) (typMask, algMask, kidMask []frontend.Variable, err error) {
	typLen := len(TypJson)
	typMask, err = api.Compiler().NewHint(hints.ContiguousMaskHint, MaxHeaderJsonLen, typOffset, typLen)
	if err != nil {
		return nil, nil, nil, err
	}

	algLen := len(AlgJson)
	algMask, err = api.Compiler().NewHint(hints.ContiguousMaskHint, MaxHeaderJsonLen, algOffset, algLen)
	if err != nil {
		return nil, nil, nil, err
	}

	kidLen := api.Add(len(KidJsonPrefix), kidValueLen)
	kidMask, err = api.Compiler().NewHint(hints.ContiguousMaskHint, MaxHeaderJsonLen, kidOffset, kidLen)
	if err != nil {
		return nil, nil, nil, err
	}

	expectedSums := []frontend.Variable{typLen, algLen, kidLen}
	hints.VerifyMasks(api, expectedSums, typMask, algMask, kidMask)

	return
}

// payloadMasksFromHints calculates the masks for the JWT payload.
// It returns the mask for the iss, the aud, the sub, and the nonce.
func payloadMasksFromHints(
	api frontend.API,
	issOffset, issValueLen frontend.Variable,
	audOffset, audValueLen frontend.Variable,
	subOffset, subValueLen frontend.Variable,
	nonceOffset, nonceValueLen frontend.Variable,
) (issMask, audMask, subMask, nonceMask []frontend.Variable, err error) {
	issLen := api.Add(len(IssJsonPrefix), issValueLen)
	issMask, err = api.Compiler().NewHint(hints.ContiguousMaskHint, MaxPayloadJsonLen, issOffset, issLen)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	audLen := api.Add(len(AudJsonPrefix), audValueLen)
	audMask, err = api.Compiler().NewHint(hints.ContiguousMaskHint, MaxPayloadJsonLen, audOffset, audLen)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	subLen := api.Add(len(SubJsonPrefix), subValueLen)
	subMask, err = api.Compiler().NewHint(hints.ContiguousMaskHint, MaxPayloadJsonLen, subOffset, subLen)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	nonceLen := api.Add(len(NonceJsonPrefix), nonceValueLen)
	nonceMask, err = api.Compiler().NewHint(hints.ContiguousMaskHint, MaxPayloadJsonLen, nonceOffset, nonceLen)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	expectedSums := []frontend.Variable{issLen, audLen, subLen, nonceLen}
	hints.VerifyMasks(api, expectedSums, issMask, audMask, subMask, nonceMask)

	return
}
