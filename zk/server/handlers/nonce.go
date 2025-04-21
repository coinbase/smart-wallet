package handlers

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/coinbase/smart-wallet/circuits/utils"
)

// DeriveNonceRequest represents the request body for the /nonce endpoint
type DeriveNonceRequest struct {
	EphPubKeyHex string `json:"eph_pub_key_hex"`
	JwtRndHex    string `json:"jwt_rnd_hex"`
}

// DeriveNonceResponse represents the response body for the /nonce endpoint
type DeriveNonceResponse struct {
	Nonce string `json:"nonce"`
}

// HandleDeriveNonceRequest handles the /nonce endpoint
func HandleDeriveNonceRequest(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		log.Printf("Method not allowed: %v", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body
	var req DeriveNonceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("Error decoding request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Decode the ephemeral public key from hex
	ephPubKey, err := hex.DecodeString(strings.TrimPrefix(req.EphPubKeyHex, "0x"))
	if err != nil {
		log.Printf("Error decoding ephemeral public key: %v", err)
		http.Error(w, "Invalid ephemeral public key format", http.StatusBadRequest)
		return
	}

	// Convert ephemeral public key to 31-byte chunks
	ephPublicKeyAsElements, err := utils.EphPubKeyToElements(ephPubKey)
	if err != nil {
		log.Printf("Error converting ephemeral public key to chunks: %v", err)
		http.Error(w, "Failed to process ephemeral public key", http.StatusInternalServerError)
		return
	}

	// Convert JWT randomness from hex string to big.Int
	jwtRnd, ok := new(big.Int).SetString(strings.TrimPrefix(req.JwtRndHex, "0x"), 16)
	if !ok {
		log.Printf("Error converting JWT randomness to big.Int: %v", req.JwtRndHex)
		http.Error(w, "Invalid JWT randomness format", http.StatusBadRequest)
		return
	}

	// Call DeriveNonce function
	nonce, err := utils.DeriveNonce(ephPublicKeyAsElements, jwtRnd)
	if err != nil {
		log.Printf("Error deriving nonce: %v", err)
		http.Error(w, "Failed to derive nonce", http.StatusInternalServerError)
		return
	}

	// Return the nonce
	nonceBase64 := base64.RawURLEncoding.EncodeToString(nonce.Bytes())
	response := DeriveNonceResponse{
		Nonce: nonceBase64,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
