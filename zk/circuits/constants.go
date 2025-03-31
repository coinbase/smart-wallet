package circuits

const (
	MaxJwtBase64Len    = 2048
	MaxJwtHeaderKidLen = 128
)

const expectedTypJson = `"typ":"JWT"`
const expectedAlgJson = `"alg":"ES256"`
const expectedCrvJson = `"crv":"P-256"`
const expectedKidPrefixJson = `"kid":`

const expectedSubPrefixJson = `"sub":"`
const expectedIssPrefixJson = `"iss":"`
const expectedAudPrefixJson = `"aud":"`
