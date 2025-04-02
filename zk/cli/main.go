package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"strings"

	"encoding/base64"
	"encoding/json"

	"github.com/coinbase/smart-wallet/circuits/circuits"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/urfave/cli/v2"
)

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
	{
		Name:  "setup",
		Usage: "Run the setup ceremony",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "circuit",
				Aliases:  []string{"c"},
				Usage:    "Path to the circuit file",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "proving-key",
				Aliases:  []string{"pk"},
				Usage:    "Output path for the proving key",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "verification-key",
				Aliases:  []string{"vk"},
				Usage:    "Output path for the verification key",
				Required: true,
			},
		},
		Action: SetupCircuit,
	},
	{
		Name:  "contract",
		Usage: "Generate the Solidity verifier contract",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "verification-key",
				Aliases:  []string{"vk"},
				Usage:    "Path to the verification key",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "output",
				Aliases:  []string{"o"},
				Usage:    "Output path for the Solidity verifier contract",
				Required: true,
			},
		},
		Action: GenerateContract,
	},
	{
		Name:  "prove",
		Usage: "Generate a proof",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "circuit",
				Aliases:  []string{"c"},
				Usage:    "Path to the circuit file",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "proving-key",
				Aliases:  []string{"pk"},
				Usage:    "Path to the proving key",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "jwt",
				Aliases:  []string{"j"},
				Usage:    "JWT to prove",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "output",
				Aliases:  []string{"o"},
				Usage:    "Output path for the proof file",
				Required: true,
			},
		},
		Action: GenerateProof,
	},
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
	zkCircuit := circuits.ZkLoginCircuit{
		// Set public inputs values.
		JwtHeaderKidValue: make([]uints.U8, circuits.MaxJwtHeaderKidValueLen),

		// Set private inputs sizes.
		JwtHeader:  make([]uints.U8, circuits.MaxJwtHeaderLen),
		JwtPayload: make([]uints.U8, circuits.MaxJwtPayloadLen),
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

func SetupCircuit(cCtx *cli.Context) error {
	fmt.Println("Reading circuit...")
	circuitPath := cCtx.String("circuit")
	circuit, err := os.ReadFile(circuitPath)
	if err != nil {
		return fmt.Errorf("failed to read circuit file: %w", err)
	}

	cs := groth16.NewCS(ecc.BN254)
	cs.ReadFrom(bytes.NewReader(circuit))

	fmt.Println("Running setup ceremony...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		return fmt.Errorf("failed to setup circuit: %w", err)
	}

	fmt.Println("Writing proving key...")
	pkPath := cCtx.String("pk")
	pkBuf := bytes.NewBuffer(nil)
	pk.WriteRawTo(pkBuf)
	if err := os.WriteFile(pkPath, pkBuf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}
	fmt.Printf("Successfully wrote proving key to %s\n", pkPath)

	fmt.Println("Writing verification key...")
	vkPath := cCtx.String("vk")
	vkBuf := bytes.NewBuffer(nil)
	vk.WriteRawTo(vkBuf)
	if err := os.WriteFile(vkPath, vkBuf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}
	fmt.Printf("Successfully wrote verification key to %s\n", vkPath)
	return nil
}

func GenerateContract(cCtx *cli.Context) error {
	fmt.Println("Reading verification key...")
	vkPath := cCtx.String("vk")
	vkBytes, err := os.ReadFile(vkPath)
	if err != nil {
		return fmt.Errorf("failed to read verification key file: %w", err)
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	vk.ReadFrom(bytes.NewReader(vkBytes))

	fmt.Println("Writing contract...")
	f, err := os.Create(cCtx.String("output"))
	if err != nil {
		return fmt.Errorf("failed to create contract file: %w", err)
	}
	vk.ExportSolidity(f)

	fmt.Printf("Successfully wrote contract to %s\n", cCtx.String("output"))

	return nil
}

func GenerateProof(cCtx *cli.Context) error {
	jwt := cCtx.String("jwt")

	fmt.Println("Processing JWT...")
	sections := strings.Split(jwt, ".")
	if len(sections) < 2 || len(sections) > 3 {
		return fmt.Errorf("invalid JWT format: expected 2 or 3 sections, got %d", len(sections))
	}

	// Process the header.
	headerB64 := sections[0]
	headerJSON, typOffset, algOffset, kidOffset, kidValueLen, kidValue, err := processJwtHeader(headerB64)
	if err != nil {
		return fmt.Errorf("failed to process JWT header: %w", err)
	}

	// Process the payload.
	payloadB64 := sections[1]
	payloadJSON, issOffset, issValueLen, audOffset, audValueLen, subOffset, subValueLen, issValue, audValue, subValue, err := processJwtPayload(payloadB64)
	if err != nil {
		return fmt.Errorf("failed to process JWT payload: %w", err)
	}

	// Compute the hashes.
	fmt.Println("Computing hashes...")
	secretBytes := make([]uint8, circuits.MaxJwtPayloadIssLen+circuits.MaxJwtPayloadAudLen+circuits.MaxJwtPayloadSubLen)
	copy(secretBytes, issValue)
	copy(secretBytes[circuits.MaxJwtPayloadIssLen:], audValue)
	copy(secretBytes[circuits.MaxJwtPayloadIssLen+circuits.MaxJwtPayloadAudLen:], subValue)
	derivedHashBytes := sha256.Sum256(secretBytes)
	derivedHash := new(big.Int).SetBytes(derivedHashBytes[1:])

	jwtBase64 := fmt.Sprintf("%s.%s", headerB64, payloadB64)
	jwtHashBytes := sha256.Sum256([]byte(jwtBase64))
	jwtHash := new(big.Int).SetBytes(jwtHashBytes[1:])

	fmt.Println("Generating witness...")
	witness, err := generateWitness(
		headerJSON, payloadJSON,
		len(headerB64), len(payloadB64),
		kidValue,
		jwtHash, derivedHash,
		typOffset, algOffset, kidOffset, kidValueLen,
		issOffset, issValueLen, audOffset, audValueLen, subOffset, subValueLen,
	)
	if err != nil {
		return fmt.Errorf("failed to generate witness: %w", err)
	}

	fmt.Println("Reading circuit...")
	circuitPath := cCtx.String("circuit")
	circuit, err := os.ReadFile(circuitPath)
	if err != nil {
		return fmt.Errorf("failed to read circuit file: %w", err)
	}
	cs := groth16.NewCS(ecc.BN254)
	cs.ReadFrom(bytes.NewReader(circuit))

	fmt.Println("Reading proving key...")
	pkPath := cCtx.String("pk")
	pkBytes, err := os.ReadFile(pkPath)
	if err != nil {
		return fmt.Errorf("failed to read proving key file: %w", err)
	}
	pk := groth16.NewProvingKey(ecc.BN254)
	pk.ReadFrom(bytes.NewReader(pkBytes))

	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		return fmt.Errorf("failed to generate proof: %w", err)
	}

	fmt.Println("Writing proof...")
	proofPath := cCtx.String("output")
	proofBuf := bytes.NewBuffer(nil)
	proof.WriteTo(proofBuf)
	if err := os.WriteFile(proofPath, proofBuf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write proof file: %w", err)
	}

	fmt.Printf("Successfully wrote proof to %s\n", proofPath)

	return nil
}

func processJwtHeader(headerB64 string) (headerJSON []byte, typOffset, algOffset, kidOffset, kidValueLen int, kidValue []byte, err error) {
	headerJSON, err = base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, 0, 0, 0, 0, nil, fmt.Errorf("failed to decode header: %w", err)
	}

	var header map[string]json.RawMessage
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, 0, 0, 0, 0, nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	typ := header["typ"]
	if string(typ) != `"JWT"` {
		return nil, 0, 0, 0, 0, nil, fmt.Errorf("invalid JWT header: expected 'JWT', got '%s'", typ)
	}

	alg := header["alg"]
	if string(alg) != `"RS256"` {
		return nil, 0, 0, 0, 0, nil, fmt.Errorf("invalid JWT header: expected 'RS256', got '%s'", alg)
	}

	kid := header["kid"]
	if kid == nil {
		return nil, 0, 0, 0, 0, nil, fmt.Errorf("invalid JWT header: expected 'kid' field")
	}

	typOffset = strings.Index(string(headerJSON), `"typ"`)
	algOffset = strings.Index(string(headerJSON), `"alg"`)
	kidOffset = strings.Index(string(headerJSON), `"kid"`)
	kidValueLen = len(kid)

	return headerJSON, typOffset, algOffset, kidOffset, kidValueLen, kid, nil
}

func processJwtPayload(payloadB64 string) (payloadJSON []byte, issOffset, issValueLen, audOffset, audValueLen, subOffset, subValueLen int, issValue, audValue, subValue []byte, err error) {
	payloadJSON, err = base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, 0, 0, 0, 0, 0, 0, nil, nil, nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	var payload map[string]json.RawMessage
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, 0, 0, 0, 0, 0, 0, nil, nil, nil, fmt.Errorf("failed to parse JWT payload: %w", err)
	}

	issOffset = strings.Index(string(payloadJSON), `"iss"`)
	issValueLen = len(payload["iss"])

	audOffset = strings.Index(string(payloadJSON), `"aud"`)
	audValueLen = len(payload["aud"])

	subOffset = strings.Index(string(payloadJSON), `"sub"`)
	subValueLen = len(payload["sub"])

	return payloadJSON, issOffset, issValueLen, audOffset, audValueLen, subOffset, subValueLen, payload["iss"], payload["aud"], payload["sub"], nil
}

func generateWitness(
	jwtHeaderJson, jwtPayloadJson []byte,
	lenJwtHeaderBase64, lenJwtPayloadBase64 int,

	// Public inputs.
	kidValue []byte,
	jwtHash, derivedHash *big.Int,

	// Private inputs.
	typOffset, algOffset, kidOffset, kidValueLen int,
	issOffset, issValueLen, audOffset, audValueLen, subOffset, subValueLen int,
) (witness.Witness, error) {

	witnessJwtHeader := make([]uints.U8, circuits.MaxJwtHeaderLen)
	for i := range jwtHeaderJson {
		witnessJwtHeader[i] = uints.NewU8(jwtHeaderJson[i])
	}

	witnessJwtPayload := make([]uints.U8, circuits.MaxJwtPayloadLen)
	for i := range jwtPayloadJson {
		witnessJwtPayload[i] = uints.NewU8(jwtPayloadJson[i])
	}

	witnessJwtHeaderKidValue := make([]uints.U8, circuits.MaxJwtHeaderKidValueLen)
	for i := range kidValue {
		witnessJwtHeaderKidValue[i] = uints.NewU8(kidValue[i])
	}

	assignment := &circuits.ZkLoginCircuit{
		// // Public inputs.
		JwtHeaderKidValue: witnessJwtHeaderKidValue,
		JwtHash:           jwtHash,
		DerivedHash:       derivedHash,

		// Private inputs.
		JwtHeader:           witnessJwtHeader,
		JwtHeaderBase64Len:  lenJwtHeaderBase64,
		JwtPayload:          witnessJwtPayload,
		JwtPayloadBase64Len: lenJwtPayloadBase64,

		TypOffset:   typOffset,
		AlgOffset:   algOffset,
		KidOffset:   kidOffset,
		KidValueLen: kidValueLen,

		IssOffset:   issOffset,
		IssValueLen: issValueLen,
		AudOffset:   audOffset,
		AudValueLen: audValueLen,
		SubOffset:   subOffset,
		SubValueLen: subValueLen,
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to create witness: %w", err)
	}

	return witness, nil
}
