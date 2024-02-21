export const ALGO_NAMES = {
  ECDH: "ECDH",
  AES_CTR: "AES-CTR",
  RSA_OEAP: "RSA-OAEP",
};

export const ECDH_PARAMS = {
  name: ALGO_NAMES.ECDH,
  namedCurve: "P-521",
};

export const AES_PARAMS = {
  name: ALGO_NAMES.AES_CTR,
  length: 256,
};
