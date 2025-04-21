package main

import (
	"log"
	"net/http"
	"os"

	"github.com/coinbase/smart-wallet/circuits/server/handlers"
)

// corsMiddleware adds CORS headers to the response
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Set CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Call the next handler
		next(w, r)
	}
}

func main() {
	// Define the /proof endpoint with CORS middleware
	http.HandleFunc("/proof", corsMiddleware(handlers.HandleProofRequest))

	// Define the /zk-addr endpoint with CORS middleware
	http.HandleFunc("/zk-addr", corsMiddleware(handlers.HandleZkAddrRequest))

	// Define the /nonce endpoint with CORS middleware
	http.HandleFunc("/nonce", corsMiddleware(handlers.HandleDeriveNonceRequest))

	// Start the server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
