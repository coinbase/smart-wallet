package circuits

const (
	// JWT len must be multiple of 6bytes (48 bits) because divisible by both 6 and 8 bits.
	// This make encoding to base64 easier.
	MaxJwtHeaderLen  = 252
	MaxJwtPayloadLen = 1200

	// Max length of the base64 encoded JWT "<header>.<payload>".
	MaxJwtBase64Len = 1600

	MaxJwtHeaderKidValueLen = 64 // Google uses thumbprint which is ~40 chars

	MaxJwtPayloadIssLen = 64 // Likely too small for Microsoft.
	MaxJwtPayloadAudLen = 64
	MaxJwtPayloadSubLen = 64
)

const (
	ExpectedTypJson = `"typ":"JWT"`
	ExpectedAlgJson = `"alg":"RSA"`

	ExpectedKidPrefixJson = `"kid":`

	ExpectedIssPrefixJson = `"iss":`
	ExpectedAudPrefixJson = `"aud":`
	ExpectedSubPrefixJson = `"sub":`
)
