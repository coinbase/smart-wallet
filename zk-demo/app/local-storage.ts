type Keypair = {
  privateKey: `0x${string}`;
  address: `0x${string}`;
};

export const getKeypairs = () => {
  const storedKeypairs = JSON.parse(localStorage.getItem("keypairs") || "[]");
  return storedKeypairs as Keypair[];
};

export const addKeypair = (keypair: Keypair) => {
  const storedKeypairs = JSON.parse(localStorage.getItem("keypairs") || "[]");
  localStorage.setItem(
    "keypairs",
    JSON.stringify([...storedKeypairs, keypair])
  );
};

export const saveJWT = (jwt: string) => {
  localStorage.setItem("google_jwt", jwt);
};

export const getJWT = () => {
  return localStorage.getItem("google_jwt");
};

export const removeJWT = () => {
  localStorage.removeItem("google_jwt");
};
