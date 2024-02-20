import { ECDH_PARAMS, AES_PARAMS } from "./constants.js";

export class Ecdh {
  #ecdhKey;
  #aesKey;
  #aes;

  constructor(ecdhKey, aes) {
    this.#ecdhKey = ecdhKey;
    this.#aesKey = null;
    this.#aes = aes;
  }

  get #ownPrivateKey() {
    return this.#ecdhKey.privateKey;
  }

  static async create(aes) {
    const ecdhKey = await window.crypto.subtle.generateKey(ECDH_PARAMS, true, [
      "deriveKey",
      "deriveBits",
    ]);
    return new Ecdh(ecdhKey, aes);
  }

  get publicKey() {
    return this.#ecdhKey.publicKey;
  }

  async #deriveKey(otherPublicKey) {
    if (this.#aesKey !== null) {
      return this.#aesKey;
    }

    const algo = {
      ...ECDH_PARAMS,
      public: otherPublicKey,
    };

    return window.crypto.subtle.deriveKey(
      algo,
      this.#ownPrivateKey,
      AES_PARAMS,
      true,
      ["encrypt", "decrypt"]
    );
  }

  async encrypt(otherPublicKey, plaintext) {
    return this.#aes.encryptWithEcdh(
      this.#ecdhKey.privateKey,
      otherPublicKey,
      plaintext
    );
  }

  async decrypt(otherPublicKey, iv, cipherText, asBuffer = false) {
    return this.#aes.decryptWithEcdh(
      this.#ecdhKey.privateKey,
      otherPublicKey,
      iv,
      cipherText,
      asBuffer
    );
  }
}
