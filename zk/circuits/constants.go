package circuits

const (
	MaxJwtHeaderLen = 260
	MaxJwtLen       = MaxJwtHeaderLen + 1400

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
