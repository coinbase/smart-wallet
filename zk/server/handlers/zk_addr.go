package handlers

import (
	"encoding/json"
	"log"
	"math/big"
	"net/http"

	"github.com/coinbase/smart-wallet/circuits/utils"
)

// ZkAddrRequest represents the request body for the /zk-addr endpoint
type ZkAddrRequest struct {
	Iss         string `json:"iss"`
	Aud         string `json:"aud"`
	Sub         string `json:"sub"`
	UserSaltHex string `json:"user_salt_hex"`
}

// ZkAddrResponse represents the response body for the /zk-addr endpoint
type ZkAddrResponse struct {
	ZkAddr string `json:"zk_addr"`
}

// HandleZkAddrRequest handles the /zk-addr endpoint
func HandleZkAddrRequest(w http.ResponseWriter, r *http.Request) {
	// Only allow POST method
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request body
	var req ZkAddrRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Convert userSalt from hex string to big.Int
	userSalt, ok := new(big.Int).SetString(req.UserSaltHex, 16)
	if !ok {
		http.Error(w, "Invalid user salt format", http.StatusBadRequest)
		return
	}

	// Call DeriveZkAddr function
	zkAddr, err := utils.DeriveZkAddr(
		req.Iss,
		req.Aud,
		req.Sub,
		userSalt,
	)
	if err != nil {
		log.Printf("Error deriving ZK address: %v", err)
		http.Error(w, "Failed to derive ZK address", http.StatusInternalServerError)
		return
	}

	// Return the ZK address
	response := ZkAddrResponse{
		ZkAddr: zkAddr.String(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
