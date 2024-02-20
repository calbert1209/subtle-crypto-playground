import { AES_PARAMS, ALGO_NAMES, ECDH_PARAMS } from "../utilities/constants.js";

export class Aes {
  #textCoding;
  constructor(textCoding) {
    this.#textCoding = textCoding;
  }

  #createAESParams(iv) {
    return {
      name: ALGO_NAMES.AES_CTR,
      length: 64,
      counter: iv,
    };
  }

  #deriveKey(ownPrivateKey, otherPublicKey) {
    const algo = {
      ...ECDH_PARAMS,
      public: otherPublicKey,
    };

    return window.crypto.subtle.deriveKey(
      algo,
      ownPrivateKey,
      AES_PARAMS,
      true,
      ["encrypt", "decrypt"]
    );
  }

  generateKey() {
    const algo = {
      name: ALGO_NAMES.AES_CTR,
      length: 256,
    };

    return window.crypto.subtle.generateKey(algo, true, ["encrypt", "decrypt"]);
  }

  importJwtKey(buffer) {
    const serialData = this.#textCoding.fromArrayBuffer(buffer);
    const parsedKey = JSON.parse(serialData);
    const algo = { name: ALGO_NAMES.AES_CTR };
    return window.crypto.subtle.importKey("jwk", parsedKey, algo, true, [
      "encrypt",
      "decrypt",
    ]);
  }

  /**
   * @typedef { cipherText: string; iv: ArrayBuffer } EcdhEncryptionResult
   */

  /**
   *
   * @param {CryptoKey} key asymmetrical key for encryption
   * @param {string | ArrayBuffer} plaintext
   * @param {Uint8Array?} iv  16 byte counter value used in AES-CTR initial block
   * @returns Promise<EcdhEncryptionResult>
   */
  async encrypt(key, plaintext, iv = null) {
    const counter = iv ?? window.crypto.getRandomValues(new Uint8Array(16));
    const algo = this.#createAESParams(counter);
    const buffer =
      typeof plaintext === "string"
        ? this.#textCoding.toArrayBuffer(plaintext)
        : plaintext;

    const cipherText = await window.crypto.subtle.encrypt(algo, key, buffer);

    return {
      cipherText,
      iv: counter,
    };
  }

  /**
   *
   * @param {CryptoKey} key asymmetrical key for decryption
   * @param {Uint8Array} iv 16 byte counter previously used to encrypt the cipher text
   * @param {string} cipherText
   * @param {boolean?} asBuffer optional flag to return plain text as buffer rather than string
   * @returns Promise<ArrayBuffer | string>
   */
  async decrypt(key, iv, cipherText, asBuffer = false) {
    const algo = this.#createAESParams(iv);
    const plaintextBuffer = await window.crypto.subtle.decrypt(
      algo,
      key,
      cipherText
    );

    if (asBuffer) {
      return plaintextBuffer;
    }

    return this.#textCoding.fromArrayBuffer(plaintextBuffer);
  }

  /**
   *
   * @param {CryptoKey} privateKey  the private key held by use of this class
   * @param {CryptoKey} otherPublicKey the public key of the other key-exchange partner
   * @param {ArrayBuffer | string} plaintext
   * @returns Promise<{cipherText: string, iv: Uint8Array}>
   */
  async encryptWithEcdh(privateKey, otherPublicKey, plaintext) {
    const aesKey = await this.#deriveKey(privateKey, otherPublicKey);
    return this.encrypt(aesKey, plaintext);
  }

  /**
   *
   * @param {CryptoKey} privateKey the private key held by use of this class
   * @param {CryptoKey} otherPublicKey the public key of the other key-exchange partner
   * @param {ArrayBuffer} iv counter used to encrypt cipher text
   * @param {ArrayBuffer | string} cipherText
   * @param {boolean?} asBuffer optional flag to return plain text as buffer rather than string
   * @returns Promise<ArrayBuffer | string>
   */
  async decryptWithEcdh(privateKey, otherPublicKey, iv, cipherText, asBuffer) {
    const aesKey = await this.#deriveKey(privateKey, otherPublicKey, asBuffer);
    return this.decrypt(aesKey, iv, cipherText);
  }
}
