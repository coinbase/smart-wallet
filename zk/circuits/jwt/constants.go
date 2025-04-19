package jwt

const (
	// Max header and payload JSON lengths.
	// NOTE: must be a multiple of 3 bytes (24 bits) to ensure compatibility with Base64Encoder.
	MaxHeaderJsonLen  = 270
	MaxPayloadJsonLen = 1080

	// Max supported lengths of the kid, iss, aud, and sub values.
	MaxKidValueLen = 128
	MaxIssValueLen = 128
	MaxAudValueLen = 128
	MaxSubValueLen = 128

	// Max supported lengths of the base64 encoded JWT "<header>.<payload>".
	MaxHeaderLenBase64  = MaxHeaderJsonLen * 8 / 6
	MaxPayloadLenBase64 = MaxPayloadJsonLen * 8 / 6
	MaxLenBase64        = MaxHeaderLenBase64 + 1 + MaxPayloadLenBase64

	TypJsonKey    = "typ"
	TypJson       = `"` + TypJsonKey + `":"JWT"`
	AlgJsonKey    = "alg"
	AlgJson       = `"` + AlgJsonKey + `":"RS256"`
	KidJsonKey    = "kid"
	KidJsonPrefix = `"` + KidJsonKey + `":`

	IssJsonKey      = "iss"
	IssJsonPrefix   = `"` + IssJsonKey + `":`
	AudJsonKey      = "aud"
	AudJsonPrefix   = `"` + AudJsonKey + `":`
	SubJsonKey      = "sub"
	SubJsonPrefix   = `"` + SubJsonKey + `":`
	NonceJsonKey    = "nonce"
	NonceJsonPrefix = `"` + NonceJsonKey + `":`
)
