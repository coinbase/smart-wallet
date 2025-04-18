package main

// import (
// 	"bytes"
// 	"crypto/sha256"
// 	"encoding/base64"
// 	"encoding/hex"
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"math/big"
// 	"net/http"
// 	"os"
// 	"strings"

// 	"github.com/coinbase/smart-wallet/circuits/circuits"
// 	"github.com/consensys/gnark-crypto/ecc"
// 	"github.com/consensys/gnark/backend"
// 	"github.com/consensys/gnark/backend/groth16"
// 	"github.com/consensys/gnark/backend/solidity"
// 	"github.com/consensys/gnark/backend/witness"
// 	"github.com/consensys/gnark/constraint"
// 	"github.com/consensys/gnark/frontend"
// 	"github.com/consensys/gnark/std/math/uints"
// )

// // Global variables to store the circuit and proving key
// var (
// 	cs constraint.ConstraintSystem
// 	pk groth16.ProvingKey
// )

// // ProofRequest represents the request body for the /proof endpoint
// type ProofRequest struct {
// 	JWT      string `json:"jwt"`
// 	UserSalt string `json:"user_salt"`
// }

// // ProofResponse represents the response body for the /proof endpoint
// type ProofResponse struct {
// 	Proof string `json:"proof"`
// }

// func main() {
// 	// Load the circuit and proving key on startup
// 	if err := loadCircuitAndProvingKey(); err != nil {
// 		log.Fatalf("Failed to load circuit and proving key: %v", err)
// 	}

// 	// Define the /proof endpoint with CORS middleware
// 	http.HandleFunc("/proof", corsMiddleware(handleProofRequest))

// 	// Start the server
// 	port := os.Getenv("PORT")
// 	if port == "" {
// 		port = "8080"
// 	}

// 	log.Printf("Server starting on port %s", port)
// 	if err := http.ListenAndServe(":"+port, nil); err != nil {
// 		log.Fatalf("Server failed to start: %v", err)
// 	}
// }

// func loadCircuitAndProvingKey() error {
// 	// Load the circuit
// 	circuitPath := "../artifacts/circuit.bin"
// 	circuit, err := os.ReadFile(circuitPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read circuit file: %w", err)
// 	}

// 	cs = groth16.NewCS(ecc.BN254)
// 	cs.ReadFrom(bytes.NewReader(circuit))

// 	// Load the proving key
// 	pkPath := "../artifacts/pk.bin"
// 	pkBytes, err := os.ReadFile(pkPath)
// 	if err != nil {
// 		return fmt.Errorf("failed to read proving key file: %w", err)
// 	}

// 	pk = groth16.NewProvingKey(ecc.BN254)
// 	pk.ReadFrom(bytes.NewReader(pkBytes))

// 	log.Println("Successfully loaded circuit and proving key")
// 	return nil
// }

// func handleProofRequest(w http.ResponseWriter, r *http.Request) {
// 	// Only allow POST method
// 	if r.Method != http.MethodPost {
// 		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
// 		return
// 	}

// 	// Parse the request body
// 	var req ProofRequest
// 	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
// 		http.Error(w, "Invalid request body", http.StatusBadRequest)
// 		return
// 	}

// 	// Validate the request
// 	if req.JWT == "" || req.UserSalt == "" {
// 		http.Error(w, "JWT and user_salt are required", http.StatusBadRequest)
// 		return
// 	}

// 	// Generate the proof
// 	proofBytes, err := generateProof(req.JWT, req.UserSalt)
// 	if err != nil {
// 		log.Printf("Error generating proof: %v", err)
// 		http.Error(w, "Failed to generate proof", http.StatusInternalServerError)
// 		return
// 	}

// 	// Return the proof
// 	response := ProofResponse{
// 		Proof: base64.RawURLEncoding.EncodeToString(proofBytes),
// 	}

// 	w.Header().Set("Content-Type", "application/json")
// 	json.NewEncoder(w).Encode(response)
// }

// func generateProof(jwt, userSalt string) ([]byte, error) {
// 	userSaltBytes, err := hex.DecodeString(strings.TrimPrefix(userSalt, "0x"))
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to decode user salt: %w", err)
// 	}

// 	// Process the JWT
// 	sections := strings.Split(jwt, ".")
// 	if len(sections) < 2 || len(sections) > 3 {
// 		return nil, fmt.Errorf("invalid JWT format: expected 2 or 3 sections, got %d", len(sections))
// 	}

// 	// Process the header
// 	headerB64 := sections[0]

// 	// Process the payload
// 	payloadB64 := sections[1]
// 	payloadJSON, issOffset, issLen, audOffset, audLen, subOffset, subLen, nonceOffset, nonceLen, iss, aud, sub, nonce, err := processJwtPayload(payloadB64)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to process JWT payload: %w", err)
// 	}

// 	// Compute the hashes
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

// 	// Generate witness
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
// 		return nil, fmt.Errorf("failed to generate witness: %w", err)
// 	}

// 	// Generate proof
// 	proof, err := groth16.Prove(cs, pk, witness, solidity.WithProverTargetSolidityVerifier(backend.GROTH16))
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to generate proof: %w", err)
// 	}

// 	// Serialize the proof
// 	proofBuf := bytes.NewBuffer(nil)
// 	proof.WriteRawTo(proofBuf)

// 	return proofBuf.Bytes(), nil
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
// 		// Public inputs.
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

// // corsMiddleware adds CORS headers to the response
// func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
// 	return func(w http.ResponseWriter, r *http.Request) {
// 		// Set CORS headers
// 		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
// 		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
// 		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

// 		// Handle preflight requests
// 		if r.Method == "OPTIONS" {
// 			w.WriteHeader(http.StatusOK)
// 			return
// 		}

// 		// Call the next handler
// 		next(w, r)
// 	}
// }
