package jwt

const (
	// JWT len must be multiple of 3bytes (24 bits) because divisible by both 6 and 8 bits.
	// This make encoding to base64 easier.
	MaxHeaderJsonLen  = 270
	MaxPayloadJsonLen = 1080

	MaxKidValueLen = 128
	MaxIssValueLen = 128
	MaxAudValueLen = 128
	MaxSubValueLen = 128

	// Max length of the base64 encoded JWT "<header>.<payload>".
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
