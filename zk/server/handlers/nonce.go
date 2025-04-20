package handlers

import (
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
	UserSaltHex  string `json:"user_salt_hex"`
}

// DeriveNonceResponse represents the response body for the /nonce endpoint
type DeriveNonceResponse struct {
	Nonce string `json:"nonce"`
}

// HandleDeriveNonceRequest handles the /nonce endpoint
func HandleDeriveNonceRequest(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body
	var req DeriveNonceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Decode the ephemeral public key from hex
	ephPubKey, err := hex.DecodeString(strings.TrimPrefix(req.EphPubKeyHex, "0x"))
	if err != nil {
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

	// Convert user salt from hex string to big.Int
	userSalt, ok := new(big.Int).SetString(req.UserSaltHex, 16)
	if !ok {
		http.Error(w, "Invalid user salt format", http.StatusBadRequest)
		return
	}

	// Call DeriveNonce function
	nonce, err := utils.DeriveNonce(ephPublicKeyAsElements, userSalt)
	if err != nil {
		log.Printf("Error deriving nonce: %v", err)
		http.Error(w, "Failed to derive nonce", http.StatusInternalServerError)
		return
	}

	// Return the nonce
	response := DeriveNonceResponse{
		Nonce: nonce.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
