type IDPKey = {
  kid: string;
  n: string;
  e: string;
};

type IDPResp = {
  keys: IDPKey[];
};

export const getGoogleIDPKey = async (kid: string) => {
  const resp = await fetch("https://www.googleapis.com/oauth2/v3/certs");
  const data = (await resp.json()) as IDPResp;
  return data.keys.find((key) => key.kid === kid);
};
