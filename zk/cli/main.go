package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/urfave/cli/v2"

	"github.com/coinbase/smart-wallet/circuits/circuits"
	"github.com/coinbase/smart-wallet/circuits/circuits/jwt"
	"github.com/coinbase/smart-wallet/circuits/circuits/rsa"
)

// {"typ":"JWT","alg":"RS256","kid":"1234567890"}
// {"iss":"google.com","aud":"csw.com","sub":"xenoliss","nonce":"c29tZV9ldGhlcmV1bV9hZGRyZXNz"}

var commands = []*cli.Command{
	{
		Name:  "compile",
		Usage: "Compile the circuit",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "output",
				Aliases:  []string{"o"},
				Usage:    "Output path for the compiled circuit",
				Required: true,
			},
		},
		Action: CompileCircuit,
	},
	// {
	// 	Name:  "setup",
	// 	Usage: "Run the setup ceremony",
	// 	Flags: []cli.Flag{
	// 		&cli.StringFlag{
	// 			Name:     "circuit",
	// 			Aliases:  []string{"c"},
	// 			Usage:    "Path to the circuit file",
	// 			Required: true,
	// 		},
	// 		&cli.StringFlag{
	// 			Name:     "proving-key",
	// 			Aliases:  []string{"pk"},
	// 			Usage:    "Output path for the proving key",
	// 			Required: true,
	// 		},
	// 		&cli.StringFlag{
	// 			Name:     "verification-key",
	// 			Aliases:  []string{"vk"},
	// 			Usage:    "Output path for the verification key",
	// 			Required: true,
	// 		},
	// 	},
	// 	Action: SetupCircuit,
	// },
	// {
	// 	Name:  "contract",
	// 	Usage: "Generate the Solidity verifier contract",
	// 	Flags: []cli.Flag{
	// 		&cli.StringFlag{
	// 			Name:     "verification-key",
	// 			Aliases:  []string{"vk"},
	// 			Usage:    "Path to the verification key",
	// 			Required: true,
	// 		},
	// 		&cli.StringFlag{
	// 			Name:     "output",
	// 			Aliases:  []string{"o"},
	// 			Usage:    "Output path for the Solidity verifier contract",
	// 			Required: true,
	// 		},
	// 	},
	// 	Action: GenerateContract,
	// },
	// {
	// 	Name:  "prove",
	// 	Usage: "Generate a proof",
	// 	Flags: []cli.Flag{
	// 		&cli.StringFlag{
	// 			Name:     "circuit",
	// 			Aliases:  []string{"c"},
	// 			Usage:    "Path to the circuit file",
	// 			Required: true,
	// 		},
	// 		&cli.StringFlag{
	// 			Name:     "proving-key",
	// 			Aliases:  []string{"pk"},
	// 			Usage:    "Path to the proving key",
	// 			Required: true,
	// 		},
	// 		&cli.StringFlag{
	// 			Name:     "jwt",
	// 			Aliases:  []string{"j"},
	// 			Usage:    "JWT to prove",
	// 			Required: true,
	// 			Action: func(cCtx *cli.Context, j string) error {
	// 				sections := strings.Split(j, ".")
	// 				if len(sections) < 2 || len(sections) > 3 {
	// 					return fmt.Errorf("invalid JWT format: expected 2 or 3 sections, got %d", len(sections))
	// 				}
	// 				return nil
	// 			},
	// 		},
	// 		&cli.StringFlag{
	// 			Name:     "user-salt",
	// 			Aliases:  []string{"salt", "s"},
	// 			Usage:    "User salt",
	// 			Required: true,
	// 			Action: func(cCtx *cli.Context, s string) error {
	// 				s = strings.TrimPrefix(s, "0x")
	// 				if _, err := hex.DecodeString(s); err != nil {
	// 					return fmt.Errorf("invalid hex string: %w", err)
	// 				}

	// 				if len(s) > circuits.UserSaltLen*2 {
	// 					return fmt.Errorf("salt too long: max 32 bytes (64 hex characters)")
	// 				}
	// 				return nil
	// 			},
	// 		},
	// 		&cli.StringFlag{
	// 			Name:     "output",
	// 			Aliases:  []string{"o"},
	// 			Usage:    "Output path for the proof file",
	// 			Required: true,
	// 		},
	// 	},
	// 	Action: GenerateProof,
	// },
}

func main() {
	app := &cli.App{
		Name:     "zklogin-cli",
		Usage:    "ZkLogin proof tools",
		Commands: commands,
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func CompileCircuit(cCtx *cli.Context) error {
	zkCircuit := circuits.ZkLoginCircuit[rsa.Mod1e2048]{
		// Public inputs sizes.
		EphemeralPublicKey: make([]frontend.Variable, circuits.MaxEphemeralPublicKeyChunks),
		JwtHeaderJson:      make([]uints.U8, jwt.MaxHeaderJsonLen),
		KidValue:           make([]uints.U8, jwt.MaxKidValueLen),

		// Private inputs sizes.
		JwtPayloadJson: make([]uints.U8, jwt.MaxPayloadJsonLen),
		IssValue:       make([]uints.U8, jwt.MaxIssValueLen),
		AudValue:       make([]uints.U8, jwt.MaxAudValueLen),
		SubValue:       make([]uints.U8, jwt.MaxSubValueLen),
	}

	fmt.Println("Compiling circuit...")
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &zkCircuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}

	var buf bytes.Buffer
	cs.WriteTo(&buf)

	fmt.Println("Writing compiled circuit...")
	outputPath := cCtx.String("output")
	if err := os.WriteFile(outputPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}
	fmt.Printf("Successfully wrote compiled circuit to %s\n", outputPath)

	return nil
}

// func SetupCircuit(cCtx *cli.Context) error {
// 	fmt.Println("Reading circuit...")
// 	circuitPath := cCtx.String("circuit")
// 	circuit, err := os.ReadFile(circuitPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read circuit file: %w", err)
// 	}

// 	cs := groth16.NewCS(ecc.BN254)
// 	cs.ReadFrom(bytes.NewReader(circuit))

// 	fmt.Println("Running setup ceremony...")
// 	pk, vk, err := groth16.Setup(cs)
// 	if err != nil {
// 		return fmt.Errorf("failed to setup circuit: %w", err)
// 	}

// 	fmt.Println("Writing proving key...")
// 	pkPath := cCtx.String("pk")
// 	pkBuf := bytes.NewBuffer(nil)
// 	pk.WriteRawTo(pkBuf)
// 	if err := os.WriteFile(pkPath, pkBuf.Bytes(), 0644); err != nil {
// 		return fmt.Errorf("failed to write output file: %w", err)
// 	}
// 	fmt.Printf("Successfully wrote proving key to %s\n", pkPath)

// 	fmt.Println("Writing verification key...")
// 	vkPath := cCtx.String("vk")
// 	vkBuf := bytes.NewBuffer(nil)
// 	vk.WriteRawTo(vkBuf)
// 	if err := os.WriteFile(vkPath, vkBuf.Bytes(), 0644); err != nil {
// 		return fmt.Errorf("failed to write output file: %w", err)
// 	}
// 	fmt.Printf("Successfully wrote verification key to %s\n", vkPath)
// 	return nil
// }

// func GenerateContract(cCtx *cli.Context) error {
// 	fmt.Println("Reading verification key...")
// 	vkPath := cCtx.String("vk")
// 	vkBytes, err := os.ReadFile(vkPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read verification key file: %w", err)
// 	}

// 	vk := groth16.NewVerifyingKey(ecc.BN254)
// 	vk.ReadFrom(bytes.NewReader(vkBytes))

// 	fmt.Println("Writing contract...")
// 	f, err := os.Create(cCtx.String("output"))
// 	if err != nil {
// 		return fmt.Errorf("failed to create contract file: %w", err)
// 	}
// 	vk.ExportSolidity(f)

// 	fmt.Printf("Successfully wrote contract to %s\n", cCtx.String("output"))

// 	return nil
// }

// func GenerateProof(cCtx *cli.Context) error {
// 	jwt := cCtx.String("jwt")
// 	userSalt := cCtx.String("user-salt")
// 	userSaltBytes, _ := hex.DecodeString(strings.TrimPrefix(userSalt, "0x"))

// 	fmt.Println("Processing JWT...")
// 	sections := strings.Split(jwt, ".")

// 	// Process the header.
// 	headerB64 := sections[0]

// 	// Process the payload.
// 	payloadB64 := sections[1]
// 	payloadJSON, issOffset, issLen, audOffset, audLen, subOffset, subLen, nonceOffset, nonceLen, iss, aud, sub, nonce, err := processJwtPayload(payloadB64)
// 	if err != nil {
// 		return fmt.Errorf("failed to process JWT payload: %w", err)
// 	}

// 	// Compute the hashes.
// 	fmt.Println("Computing hashes...")
// 	secretBytes := make([]uint8, circuits.MaxIssLen+circuits.MaxAudLen+circuits.MaxSubLen+circuits.UserSaltLen)
// 	copy(secretBytes, iss)
// 	copy(secretBytes[circuits.MaxIssLen:], aud)
// 	copy(secretBytes[circuits.MaxIssLen+circuits.MaxAudLen:], sub)
// 	copy(secretBytes[circuits.MaxIssLen+circuits.MaxAudLen+circuits.MaxSubLen:], userSaltBytes)
// 	zkAddrBytes := sha256.Sum256(secretBytes)
// 	zkAddr := new(big.Int).SetBytes(zkAddrBytes[:31]) // Skip the least significant byte (index 31) to fit the BN254 scalar field.

// 	jwtBase64 := fmt.Sprintf("%s.%s", headerB64, payloadB64)
// 	jwtHashBytes := sha256.Sum256([]byte(jwtBase64))
// 	jwtHash := new(big.Int).SetBytes(jwtHashBytes[:31]) // Skip the least significant byte (index 31) to fit the BN254 scalar field.

// 	fmt.Println("Generating witness...")
// 	witness, err := generateWitness(
// 		// Public inputs.
// 		headerB64,
// 		nonce,
// 		jwtHash,
// 		zkAddr,

// 		// Private inputs.
// 		payloadJSON,
// 		len(payloadB64),
// 		issOffset, issLen,
// 		audOffset, audLen,
// 		subOffset, subLen,
// 		nonceOffset, nonceLen,
// 		userSaltBytes,
// 	)
// 	if err != nil {
// 		return fmt.Errorf("failed to generate witness: %w", err)
// 	}

// 	fmt.Println("Reading circuit...")
// 	circuitPath := cCtx.String("circuit")
// 	circuit, err := os.ReadFile(circuitPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read circuit file: %w", err)
// 	}
// 	cs := groth16.NewCS(ecc.BN254)
// 	cs.ReadFrom(bytes.NewReader(circuit))

// 	fmt.Println("Reading proving key...")
// 	pkPath := cCtx.String("pk")
// 	pkBytes, err := os.ReadFile(pkPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read proving key file: %w", err)
// 	}
// 	pk := groth16.NewProvingKey(ecc.BN254)
// 	pk.ReadFrom(bytes.NewReader(pkBytes))

// 	fmt.Println("Generating proof...")
// 	proof, err := groth16.Prove(cs, pk, witness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
// 	if err != nil {
// 		return fmt.Errorf("failed to generate proof: %w", err)
// 	}

// 	fmt.Println("Writing proof...")
// 	proofPath := cCtx.String("output")
// 	proofBuf := bytes.NewBuffer(nil)
// 	proof.WriteRawTo(proofBuf)
// 	if err := os.WriteFile(proofPath, proofBuf.Bytes(), 0644); err != nil {
// 		return fmt.Errorf("failed to write proof file: %w", err)
// 	}

// 	fmt.Printf("Successfully wrote proof to %s\n", proofPath)

// 	return nil
// }

// func processJwtPayload(payloadB64 string) (payloadJSON []byte, issOffset, issLen, audOffset, audLen, subOffset, subLen, nonceOffset, nonceLen int, iss, audValue, subValue, nonce []byte, err error) {
// 	payloadJSON, err = base64.RawURLEncoding.DecodeString(payloadB64)
// 	if err != nil {
// 		return nil, 0, 0, 0, 0, 0, 0, 0, 0, nil, nil, nil, nil, fmt.Errorf("failed to decode payload: %w", err)
// 	}

// 	var payload map[string]json.RawMessage
// 	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
// 		return nil, 0, 0, 0, 0, 0, 0, 0, 0, nil, nil, nil, nil, fmt.Errorf("failed to parse JWT payload: %w", err)
// 	}

// 	issOffset = strings.Index(string(payloadJSON), `"iss"`)
// 	iss = payload["iss"]
// 	issLen = len(iss)

// 	audOffset = strings.Index(string(payloadJSON), `"aud"`)
// 	audValue = payload["aud"]
// 	audLen = len(audValue)

// 	subOffset = strings.Index(string(payloadJSON), `"sub"`)
// 	subValue = payload["sub"]
// 	subLen = len(subValue)

// 	nonceOffset = strings.Index(string(payloadJSON), `"nonce"`)
// 	nonce = payload["nonce"]
// 	nonceLen = len(nonce)

// 	return payloadJSON, issOffset, issLen, audOffset, audLen, subOffset, subLen, nonceOffset, nonceLen, iss, audValue, subValue, nonce, nil
// }

// func generateWitness(
// 	// Public inputs.
// 	jwtHeaderBase64 string,
// 	nonce []byte,
// 	jwtHash,
// 	zkAddr *big.Int,

// 	// Private inputs.
// 	jwtPayloadJson []byte, lenJwtPayloadBase64 int,
// 	issOffset, issLen int,
// 	audOffset, audLen int,
// 	subOffset, subLen int,
// 	nonceOffset, nonceLen int,
// 	userSalt []byte,
// ) (witness.Witness, error) {

// 	witnessNonce := make([]uints.U8, circuits.MaxNonceLen)
// 	for i := range nonce {
// 		witnessNonce[i] = uints.NewU8(nonce[i])
// 	}

// 	witnessJwtHeaderBase64 := make([]uints.U8, circuits.MaxJwtHeaderLenBase64)
// 	for i := range jwtHeaderBase64 {
// 		witnessJwtHeaderBase64[i] = uints.NewU8(jwtHeaderBase64[i])
// 	}

// 	witnessJwtPayloadJson := make([]uints.U8, circuits.MaxJwtPayloadJsonLen)
// 	for i := range jwtPayloadJson {
// 		witnessJwtPayloadJson[i] = uints.NewU8(jwtPayloadJson[i])
// 	}

// 	witnessUserSalt := make([]uints.U8, circuits.UserSaltLen)
// 	for i := range userSalt {
// 		witnessUserSalt[i] = uints.NewU8(userSalt[i])
// 	}

// 	assignment := &circuits.ZkLoginCircuit{
// 		// // Public inputs.
// 		JwtHeaderBase64:    witnessJwtHeaderBase64,
// 		JwtHeaderBase64Len: len(jwtHeaderBase64),
// 		Nonce:              witnessNonce,
// 		JwtHash:            jwtHash,
// 		ZkAddr:             zkAddr,

// 		// Private inputs.
// 		JwtPayloadJson:      witnessJwtPayloadJson,
// 		JwtPayloadBase64Len: lenJwtPayloadBase64,

// 		IssOffset:   issOffset,
// 		IssLen:      issLen,
// 		AudOffset:   audOffset,
// 		AudLen:      audLen,
// 		SubOffset:   subOffset,
// 		SubLen:      subLen,
// 		NonceOffset: nonceOffset,
// 		NonceLen:    nonceLen,

// 		UserSalt: witnessUserSalt,
// 	}

// 	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to create witness: %w", err)
// 	}

// 	return witness, nil
// }
