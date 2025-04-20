export type Keypair = {
  privateKey: `0x${string}`;
  address: `0x${string}`;
  jwtRnd: string;
};

export const setNonceToLocalStorage = (nonce: string) => {
  localStorage.setItem("nonce", nonce);
};

export const getNonceFromLocalStorage = () => {
  return localStorage.getItem("nonce");
};

export const removeNonceFromLocalStorage = () => {
  return localStorage.removeItem("nonce");
};

export const getKeypairsFromLocalStorage = () => {
  const storedKeypairs = JSON.parse(localStorage.getItem("keypairs") || "[]");
  return storedKeypairs as Keypair[];
};

export const addKeypairToLocalStorage = (keypair: Keypair) => {
  const storedKeypairs = JSON.parse(localStorage.getItem("keypairs") || "[]");
  localStorage.setItem(
    "keypairs",
    JSON.stringify([...storedKeypairs, keypair])
  );
};

export const setJwtToLocalStorage = (jwt: string) => {
  localStorage.setItem("jwt", jwt);
};

export const getJwtFromLocalStorage = () => {
  return localStorage.getItem("jwt");
};

export const removeJwtFromLocalStorage = () => {
  return localStorage.getItem("jwt");
};

export const clearLocalStorage = () => {
  localStorage.removeItem("nonce");
  localStorage.removeItem("keypairs");
  localStorage.removeItem("jwt_rnd");
  localStorage.removeItem("jwt");
};
