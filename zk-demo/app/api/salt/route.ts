import { NextRequest } from "next/server";
import { keccak256, toBytes } from "viem";
import {
  ISS_BUFFER_LENGTH,
  AUD_BUFFER_LENGTH,
  SUB_BUFFER_LENGTH,
} from "../../circuit";

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

    // Validate field lengths
    if (iss.length > ISS_BUFFER_LENGTH) {
      return new Response(
        JSON.stringify({
          error: `iss length exceeds maximum of ${ISS_BUFFER_LENGTH} bytes`,
        }),
        { status: 400 }
      );
    }
    if (aud.length > AUD_BUFFER_LENGTH) {
      return new Response(
        JSON.stringify({
          error: `aud length exceeds maximum of ${AUD_BUFFER_LENGTH} bytes`,
        }),
        { status: 400 }
      );
    }
    if (sub.length > SUB_BUFFER_LENGTH) {
      return new Response(
        JSON.stringify({
          error: `sub length exceeds maximum of ${SUB_BUFFER_LENGTH} bytes`,
        }),
        { status: 400 }
      );
    }

    // Create a deterministic salt by hashing the concatenated values
    const concatenated = `${SEED}:${iss}:${aud}:${sub}`;
    const saltBytes = toBytes(concatenated);
    const salt = keccak256(saltBytes);

    return new Response(JSON.stringify({ salt }), {
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
