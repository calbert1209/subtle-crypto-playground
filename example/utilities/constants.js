export const ALGO_NAMES = {
  ECDH: "ECDH",
  AES_CTR: "AES-CTR",
  AES_GCM: "AES-GCM",
  AES_KW: "AES-KW",
  RSA_OEAP: "RSA-OAEP",
  PBKDF2: "PBKDF2",
  SHA_256: "SHA-256",
};

export const ECDH_PARAMS = {
  name: ALGO_NAMES.ECDH,
  namedCurve: "P-521",
};

export const AES_PARAMS = {
  name: ALGO_NAMES.AES_CTR,
  length: 256,
};

export const KEY_USAGE = {
  deriveBits: "deriveBits",
  deriveKey: "deriveKey",
  wrapKey: "wrapKey",
  unwrapKey: "unwrapKey",
  encrypt: "encrypt",
  decrypt: "decrypt",
}

export const KEY_FORMAT = {
  raw: "raw",
  jwk: "jwk",
  pkcs8: "pkcs8",
}