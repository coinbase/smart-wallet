package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/urfave/cli/v2"

	"github.com/coinbase/smart-wallet/circuits/circuits"
	"github.com/coinbase/smart-wallet/circuits/circuits/hints"
	"github.com/coinbase/smart-wallet/circuits/circuits/jwt"
	"github.com/coinbase/smart-wallet/circuits/circuits/rsa"
	"github.com/coinbase/smart-wallet/circuits/utils"
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
			&cli.BoolFlag{
				Name:    "profile",
				Aliases: []string{"p"},
				Usage:   "Enable profiling during compilation",
				Value:   false,
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
				Name:     "ephPubKeyHex",
				Aliases:  []string{"ephPkHex"},
				Usage:    "Ephemeral public key as hex string",
				Required: true,
				Action: func(cCtx *cli.Context, hexKey string) error {
					hexKey = strings.TrimPrefix(hexKey, "0x")
					bytes, err := hex.DecodeString(hexKey)
					if err != nil {
						return fmt.Errorf("invalid hex format for ephPubKey: %v", err)
					}
					if len(bytes) != 20 && len(bytes) != circuits.MaxEphPubKeyBytes {
						return fmt.Errorf("ephPubKey length: got %d bytes, expected 20 or %d bytes", len(bytes), circuits.MaxEphPubKeyBytes)
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:     "idpPubKeyNBase64",
				Aliases:  []string{"idpPkNB64"},
				Usage:    "IDP public key as base64 string",
				Required: true,
				Action: func(cCtx *cli.Context, base64Key string) error {
					bytes, err := base64.RawURLEncoding.DecodeString(base64Key)
					if err != nil {
						return fmt.Errorf("invalid base64 format for idpPubKeyN: %v", err)
					}
					if len(bytes) != 256 {
						return fmt.Errorf("invalid idpPubKeyN length: got %d bytes, expected 256 bytes", len(bytes))
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:     "jwtHeaderJson",
				Aliases:  []string{"jwtH"},
				Usage:    "JWT header",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "jwtPayloadJson",
				Aliases:  []string{"jwtP"},
				Usage:    "JWT payload",
				Required: true,
			},
			&cli.StringFlag{
				Name:     "jwtSignatureBase64",
				Aliases:  []string{"jwtSigB64"},
				Usage:    "JWT signature as base64 string",
				Required: true,
				Action: func(cCtx *cli.Context, signatureBase64 string) error {
					bytes, err := base64.RawURLEncoding.DecodeString(signatureBase64)
					if err != nil {
						return fmt.Errorf("invalid base64 format for jwtSignature: %v", err)
					}
					if len(bytes) != 256 {
						return fmt.Errorf("invalid jwtSignature length: got %d bytes, expected 256 bytes", len(bytes))
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:     "jwtRndHex",
				Usage:    "JWT randomness as hex string",
				Required: true,
				Action: func(cCtx *cli.Context, hexJwtRnd string) error {
					hexJwtRnd = strings.TrimPrefix(hexJwtRnd, "0x")
					_, err := hex.DecodeString(hexJwtRnd)
					if err != nil {
						return fmt.Errorf("invalid hex format for jwtRnd: %v", err)
					}

					return nil
				},
			},
			&cli.StringFlag{
				Name:     "userSaltHex",
				Usage:    "User salt as hex string",
				Required: true,
				Action: func(cCtx *cli.Context, hexUserSalt string) error {
					hexUserSalt = strings.TrimPrefix(hexUserSalt, "0x")
					_, err := hex.DecodeString(hexUserSalt)
					if err != nil {
						return fmt.Errorf("invalid hex format for userSalt: %v", err)
					}

					return nil
				},
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
	zkCircuit := circuits.ZkLoginCircuit[rsa.Mod1e2048]{
		// Semi-public inputs sizes.
		JwtHeaderJson: make([]uints.U8, jwt.MaxHeaderJsonLen),
		KidValue:      make([]uints.U8, jwt.MaxKidValueLen),

		// Private inputs sizes.
		JwtPayloadJson: make([]uints.U8, jwt.MaxPayloadJsonLen),
		IssValue:       make([]uints.U8, jwt.MaxIssValueLen),
		AudValue:       make([]uints.U8, jwt.MaxAudValueLen),
		SubValue:       make([]uints.U8, jwt.MaxSubValueLen),
	}

	fmt.Println("Compiling circuit...")
	var p *profile.Profile
	if cCtx.Bool("profile") {
		p = profile.Start()
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &zkCircuit)
	if err != nil {
		return fmt.Errorf("failed to compile circuit: %w", err)
	}

	if p != nil {
		p.Stop()
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
	ephPubKeyHex := cCtx.String("ephPubKeyHex")
	idpPubKeyNBase64 := cCtx.String("idpPubKeyNBase64")
	jwtHeaderJson := cCtx.String("jwtHeaderJson")
	jwtPayloadJson := cCtx.String("jwtPayloadJson")
	jwtSignatureBase64 := cCtx.String("jwtSignatureBase64")
	jwtRndHex := cCtx.String("jwtRndHex")
	userSaltHex := cCtx.String("userSaltHex")

	fmt.Println("Generating witness...")
	_, witness, err := utils.GenerateWitness[rsa.Mod1e2048](
		ephPubKeyHex,
		idpPubKeyNBase64,
		string(jwtHeaderJson),
		string(jwtPayloadJson),
		jwtSignatureBase64,
		jwtRndHex,
		userSaltHex,
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
	proof, err := groth16.Prove(
		cs,
		pk,
		witness,
		backend.WithSolverOptions(solver.WithHints(
			hints.OffsetHint,
			hints.JsonValueLenHint,
			hints.ContiguousMaskHint,
			hints.NonceHint,
			hints.Base64LenHint,
		)),
		solidity.WithProverTargetSolidityVerifier(backend.GROTH16),
	)
	if err != nil {
		return fmt.Errorf("failed to generate proof: %w", err)
	}

	fmt.Println("Writing proof...")
	proofPath := cCtx.String("output")
	proofBuf := bytes.NewBuffer(nil)
	proof.WriteRawTo(proofBuf)
	if err := os.WriteFile(proofPath, proofBuf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write proof file: %w", err)
	}

	fmt.Printf("Successfully wrote proof to %s\n", proofPath)

	return nil
}
