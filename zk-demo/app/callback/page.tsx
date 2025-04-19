"use client";

import { useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";

import { getKeypairs, saveJWT } from "../local-storage";
import { addressToNonce } from "../utils";

export default function CallbackPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const handleCallback = async () => {
      try {
        // Get the authorization code from the URL
        const code = searchParams.get("code");
        if (!code) {
          throw new Error("No authorization code received");
        }

        // Exchange the authorization code for tokens using our API route
        const response = await fetch("/api/auth/callback", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ code }),
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(
            errorData.error || "Failed to exchange authorization code"
          );
        }

        // Get the ID token
        const tokenData = await response.json();
        if (!tokenData.id_token) {
          throw new Error("No ID token received");
        }

        // Parse the JWT to verify the nonce
        const [, payloadBase64] = tokenData.id_token.split(".");
        const payload = JSON.parse(atob(payloadBase64));
        const nonce = payload.nonce;

        // Get the latest keypair from localStorage
        const keypairs = getKeypairs();
        const latestKeypair = keypairs[keypairs.length - 1];

        // Verify the nonce matches the latest keypair's address
        // TODO: Compute the nonce as base64(poseidon(latestKeypair.address, jwt_randomness))
        // const expectedNonce = addressToNonce(latestKeypair.address);
        const expectedNonce = "LTtll2v68lOJtOU04536biInGt7NpYkkGeIklY6SNdU";
        if (nonce !== expectedNonce) {
          throw new Error(
            "JWT nonce does not match the latest keypair's address"
          );
        }

        // Save the JWT and redirect
        saveJWT(tokenData.id_token);

        router.push("/");
      } catch (err) {
        console.error("Error processing callback:", err);
        setError(
          err instanceof Error ? err.message : "An unknown error occurred"
        );
        setLoading(false);
      }
    };

    handleCallback();
  }, [router, searchParams]);

  return (
    <main className="min-h-screen flex flex-col items-center justify-center p-4 bg-gradient-to-b from-gray-900 to-gray-800 text-white">
      <div className="w-full max-w-md p-8 rounded-xl bg-gray-800 shadow-2xl border border-gray-700">
        <h1 className="text-3xl font-bold mb-6 text-center">
          Processing Login
        </h1>

        {loading ? (
          <div className="flex flex-col items-center justify-center py-8">
            <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500 mb-4"></div>
            <p className="text-gray-300">Verifying your credentials...</p>
          </div>
        ) : (
          <div className="text-center">
            <div className="text-red-500 mb-4">
              <svg
                className="w-16 h-16 mx-auto"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                ></path>
              </svg>
            </div>
            <h2 className="text-xl font-semibold mb-2">
              Authentication Failed
            </h2>
            <p className="text-gray-300 mb-4">{error}</p>
            <button
              onClick={() => router.push("/sign-in")}
              className="py-2 px-4 bg-blue-600 hover:bg-blue-700 rounded-lg font-medium transition-colors"
            >
              Try Again
            </button>
          </div>
        )}
      </div>
    </main>
  );
}
