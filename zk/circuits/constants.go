package circuits

const (
	// JWT len must be multiple of 3bytes (24 bits) because divisible by both 6 and 8 bits.
	// This make encoding to base64 easier.
	MaxJwtHeaderLen  = 180
	MaxJwtPayloadLen = 1200

	// Max length of the base64 encoded JWT "<header>.<payload>".
	MaxJwtHeaderLenBase64  = MaxJwtHeaderLen * 8 / 6
	MaxJwtPayloadLenBase64 = MaxJwtPayloadLen * 8 / 6
	MaxJwtLenBase64        = MaxJwtHeaderLenBase64 + 1 + MaxJwtPayloadLenBase64

	MaxJwtHeaderKidValueLen = 64 // Google uses thumbprint which is ~40 chars
	MaxJwtPayloadIssLen     = 64 // Likely too small for Microsoft.
	MaxJwtPayloadAudLen     = 64
	MaxJwtPayloadSubLen     = 64
)

const (
	ExpectedTypJson = `"typ":"JWT"`
	ExpectedAlgJson = `"alg":"RSA"`

	ExpectedKidPrefixJson = `"kid":`

	ExpectedIssPrefixJson = `"iss":`
	ExpectedAudPrefixJson = `"aud":`
	ExpectedSubPrefixJson = `"sub":`
)
