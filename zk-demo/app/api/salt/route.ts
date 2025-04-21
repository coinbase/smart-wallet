import { NextRequest } from "next/server";
import { keccak256, toBytes, toHex } from "viem";

const SEED = "secret-seed";

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { iss, aud, sub } = body;

    // Validate required fields
    if (!iss || !aud || !sub) {
      return new Response(
        JSON.stringify({ error: "Missing required fields: iss, aud, sub" }),
        { status: 400 }
      );
    }

    // Create a deterministic salt by hashing the concatenated values
    const concatenated = `${SEED}:${iss}:${aud}:${sub}`;
    const saltBytes = toBytes(concatenated);
    const salt = keccak256(saltBytes, "bytes");
    const salt31Bytes = toHex(salt.slice(1));

    return new Response(JSON.stringify({ salt: salt31Bytes }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    console.error("Error generating salt:", error);
    return new Response(JSON.stringify({ error: "Failed to generate salt" }), {
      status: 500,
    });
  }
}
