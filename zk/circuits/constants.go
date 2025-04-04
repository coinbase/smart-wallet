package circuits

const (

	// JWT len must be multiple of 3bytes (24 bits) because divisible by both 6 and 8 bits.
	// This make encoding to base64 easier.
	MaxJwtPayloadJsonLen = 600
	maxJwtHeaderJsonLen  = 120

	MaxIssLen   = 64 // Likely too small for Microsoft.
	MaxAudLen   = 64
	MaxSubLen   = 64
	MaxNonceLen = 86 // (64 * 8 / 6)

	// Max length of the base64 encoded JWT "<header>.<payload>".
	MaxJwtHeaderLenBase64  = maxJwtHeaderJsonLen * 8 / 6
	MaxJwtPayloadLenBase64 = MaxJwtPayloadJsonLen * 8 / 6
	MaxJwtLenBase64        = MaxJwtHeaderLenBase64 + 1 + MaxJwtPayloadLenBase64

	UserSaltLen = 32
)

const (
	ExpectedIssPrefixJson   = `"iss":`
	ExpectedAudPrefixJson   = `"aud":`
	ExpectedSubPrefixJson   = `"sub":`
	ExpectedNoncePrefixJson = `"nonce":`
)
