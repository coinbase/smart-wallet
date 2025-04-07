"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { hexToBytes } from "viem";

import { addKeypair } from "../local-storage";

export default function SignInPage() {
  const router = useRouter();

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // Function to handle Google OAuth login
  const handleGoogleLogin = () => {
    setLoading(true);
    setError("");

    try {
      // Generate a new Ethereum private key and address
      const privateKey = generatePrivateKey();
      const account = privateKeyToAccount(privateKey);
      const address = account.address;

      const newKeypair = {
        privateKey,
        address,
      };

      addKeypair(newKeypair);

      // Convert the Ethereum address to base64 to use as nonce
      const addressBytes = hexToBytes(address);
      const base64Address = Buffer.from(addressBytes).toString("base64");

      // Google OAuth configuration
      const clientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;
      const redirectUri =
        process.env.NEXT_PUBLIC_REDIRECT_URI ||
        window.location.origin + "/callback";
      const scope = "openid"; // Only request minimal claims: sub, iss, aud

      if (!clientId) {
        throw new Error("Google OAuth client ID is not configured");
      }

      // Construct the Google OAuth URL with the base64-encoded address as nonce
      const authUrl =
        `https://accounts.google.com/o/oauth2/v2/auth?` +
        `client_id=${clientId}` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&response_type=code` +
        `&scope=${encodeURIComponent(scope)}` +
        `&nonce=${encodeURIComponent(base64Address)}` +
        `&access_type=offline` +
        `&prompt=consent`;

      // Redirect to Google OAuth
      window.location.href = authUrl;
    } catch (err) {
      console.error("Error initiating Google login:", err);
      setError("Failed to initiate login. Please try again.");
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen flex flex-col items-center justify-center p-4 bg-gradient-to-b from-gray-900 to-gray-800 text-white">
      <div className="w-full max-w-md p-8 rounded-xl bg-gray-800 shadow-2xl border border-gray-700">
        <h1 className="text-3xl font-bold mb-6 text-center">Sign In</h1>

        <div className="mb-6">
          <p className="text-gray-300 mb-2">Welcome to the zklogin demo.</p>
          <p className="text-gray-300">
            Sign in with your Google account to continue.
          </p>
          <p className="text-gray-400 text-sm mt-4">
            This will generate an Ethereum address that will be used for zklogin
            verification. The private key will be securely stored in your
            browser.
          </p>
        </div>

        <button
          onClick={handleGoogleLogin}
          disabled={loading}
          className="w-full py-3 px-4 bg-white text-gray-800 hover:bg-gray-100 rounded-lg font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
        >
          {loading ? (
            <span>Loading...</span>
          ) : (
            <>
              <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
                <path
                  fill="currentColor"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="currentColor"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="currentColor"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                />
                <path
                  fill="currentColor"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                />
              </svg>
              Sign in with Google
            </>
          )}
        </button>

        {error && (
          <div className="mt-4 p-3 bg-red-900/50 border border-red-700 rounded-lg text-red-200">
            {error}
          </div>
        )}
      </div>
    </main>
  );
}
