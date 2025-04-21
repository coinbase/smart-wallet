const BASE_URL = "https://0480fdb14c62.ngrok.app";

export const getNonce = async (addr: `0x${string}`, jwtRnd: `0x${string}`) => {
  try {
    // Prepare the request payload
    const payload = {
      eph_pub_key_hex: addr,
      jwt_rnd_hex: jwtRnd,
    };

    // Make the API call to the /nonce endpoint
    const response = await fetch(`${BASE_URL}/nonce`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    // Check if the request was successful
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Failed to get nonce: ${response.status} ${errorText}`);
    }

    // Parse the response
    const data = await response.json();
    return data.nonce;
  } catch (error) {
    console.error("Error getting nonce:", error);
    throw error;
  }
};

export const getZkAddress = async (
  iss: string,
  aud: string,
  sub: string,
  userSaltHex: string
) => {
  try {
    // Prepare the request payload
    const payload = {
      iss,
      aud,
      sub,
      user_salt_hex: userSaltHex,
    };

    // Make the API call to the /zk-addr endpoint
    const response = await fetch(`${BASE_URL}/zk-addr`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    // Check if the request was successful
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Failed to get zk address: ${response.status} ${errorText}`
      );
    }

    // Parse the response
    const data = await response.json();
    return data.zk_addr;
  } catch (error) {
    console.error("Error getting zk address:", error);
    throw error;
  }
};

export const getProof = async (
  ephPubKeyHex: `0x${string}`,
  idpPubKeyNBase64: string,
  jwtHeaderJson: string,
  jwtPayloadJson: string,
  jwtSignatureBase64: string,
  jwtRndHex: `0x${string}`,
  userSaltHex: `0x${string}`
) => {
  try {
    // Prepare the request payload
    const payload = {
      eph_pub_key_hex: ephPubKeyHex,
      idp_pub_key_n_base64: idpPubKeyNBase64,
      jwt_header_json: jwtHeaderJson,
      jwt_payload_json: jwtPayloadJson,
      jwt_signature_base64: jwtSignatureBase64,
      jwt_rnd_hex: jwtRndHex,
      user_salt_hex: userSaltHex,
    };

    // Make the API call to the /proof endpoint
    const response = await fetch(`${BASE_URL}/proof`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    // Check if the request was successful
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Failed to generate proof: ${response.status} ${errorText}`
      );
    }

    // Parse the response
    const data = await response.json();
    return data.proof;
  } catch (error) {
    console.error("Error generating proof:", error);
    throw error;
  }
};
