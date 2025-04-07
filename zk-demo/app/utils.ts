import base64url from "base64url";
import {
  decodeAbiParameters,
  encodeAbiParameters,
  parseAbiParameters,
  toBytes,
} from "viem";

export const addressToNonce = (address: `0x${string}`) => {
  const addressBytes = toBytes(
    encodeAbiParameters(parseAbiParameters("address"), [address])
  );
  return base64url(Buffer.from(addressBytes));
};

export const nonceToAddress = (nonce: string) => {
  const addressBytes = base64url.toBuffer(nonce);
  return decodeAbiParameters(parseAbiParameters("address"), addressBytes)[0];
};
