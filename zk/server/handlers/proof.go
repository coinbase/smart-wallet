package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coinbase/smart-wallet/circuits/circuits/rsa"
	"github.com/coinbase/smart-wallet/circuits/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/solidity"
	"github.com/consensys/gnark/constraint"
)

// Global variables to store the circuit and proving key
var (
	cs constraint.ConstraintSystem
	pk groth16.ProvingKey
)

// ProofRequest represents the request body for the /proof endpoint
type ProofRequest struct {
	EphPubKeyHex       string `json:"eph_pub_key_hex"`
	IdpPubKeyNBase64   string `json:"idp_pub_key_n_base64"`
	JwtHeaderJson      string `json:"jwt_header_json"`
	JwtPayloadJson     string `json:"jwt_payload_json"`
	JwtSignatureBase64 string `json:"jwt_signature_base64"`
	JwtRndHex          string `json:"jwt_rnd_hex"`
	UserSaltHex        string `json:"user_salt_hex"`
}

// ProofResponse represents the response body for the /proof endpoint
type ProofResponse struct {
	Proof string `json:"proof"`
}

// LoadCircuitAndProvingKey loads the circuit and proving key from files
func LoadCircuitAndProvingKey() error {
	// Load the circuit
	circuitPath := "../artifacts/circuit.bin"
	circuit, err := os.ReadFile(circuitPath)
	if err != nil {
		return fmt.Errorf("failed to read circuit file: %w", err)
	}

	cs = groth16.NewCS(ecc.BN254)
	cs.ReadFrom(bytes.NewReader(circuit))

	// Load the proving key
	pkPath := "../artifacts/pk.bin"
	pkBytes, err := os.ReadFile(pkPath)
	if err != nil {
		return fmt.Errorf("failed to read proving key file: %w", err)
	}

	pk = groth16.NewProvingKey(ecc.BN254)
	pk.ReadFrom(bytes.NewReader(pkBytes))

	log.Println("Successfully loaded circuit and proving key")
	return nil
}

// HandleProofRequest handles the /proof endpoint
func HandleProofRequest(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body
	var req ProofRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Generate the proof
	proofBytes, err := generateProof(
		req.EphPubKeyHex,
		req.IdpPubKeyNBase64,
		req.JwtHeaderJson,
		req.JwtPayloadJson,
		req.JwtSignatureBase64,
		req.JwtRndHex,
		req.UserSaltHex,
	)
	if err != nil {
		log.Printf("Error generating proof: %v", err)
		http.Error(w, "Failed to generate proof", http.StatusInternalServerError)
		return
	}

	// Return the proof
	response := ProofResponse{
		Proof: base64.RawURLEncoding.EncodeToString(proofBytes),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// generateProof generates a proof for the given inputs
func generateProof(ephPubKeyHex, idpPubKeyNBase64, jwtHeaderJson, jwtPayloadJson, jwtSignatureBase64, jwtRndHex, userSaltHex string) ([]byte, error) {
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
		return nil, fmt.Errorf("failed to generate witness: %w", err)
	}

	// Generate proof
	proof, err := groth16.Prove(cs, pk, witness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
	if err != nil {
		return nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	// Serialize the proof
	proofBuf := bytes.NewBuffer(nil)
	proof.WriteRawTo(proofBuf)

	return proofBuf.Bytes(), nil
}
