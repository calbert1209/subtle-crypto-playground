// cSpell:ignore Oeap, oaep

import { ALGO_NAMES } from '../utilities/constants.js';

export class RsaOeap {
  #textCoding;

  constructor(textCoding) {
    this.#textCoding = textCoding;
  }

  static get #rsaOaepParams() {
    return {
      name: ALGO_NAMES.RSA_OEAP,
    };
  }

  static async generateKey() {
    const algo = {
      name: ALGO_NAMES.RSA_OEAP,
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: "SHA-256"
    }
    return window.crypto.subtle.generateKey(algo, true, ["encrypt", "decrypt"]);
  }

  async encrypt(publicKey, plaintext) {
    const encoded = this.#textCoding.toArrayBuffer(plaintext);
    const cipherText = await window.crypto.subtle.encrypt(
      RsaOeap.#rsaOaepParams,
      publicKey,
      encoded
    );
    return cipherText;
  }

  async decrypt(privateKey, cipherText) {
    const plaintextBuffer = await window.crypto.subtle.decrypt(
      RsaOeap.#rsaOaepParams,
      privateKey,
      cipherText
    );
    return this.#textCoding.fromArrayBuffer(plaintextBuffer);
  }
}