import { ALGO_NAMES, KEY_FORMAT, KEY_USAGE } from "../utilities/constants.js";

export class AesKw {
  #textCoding;
  #salt;

  constructor(textCoding) {
    this.#textCoding = textCoding;
    this.#salt = window.crypto.getRandomValues(new Uint8Array(16));
  }

  /**
   * Get some key material to use as input to the deriveKey method.
   * The key material is a password supplied by the user.
   */
  #createKeyMaterial(plaintext) {
    const buffer = this.#textCoding.toArrayBuffer(plaintext);
    return window.crypto.subtle.importKey(
      KEY_FORMAT.raw,
      buffer,
      { name: ALGO_NAMES.PBKDF2 },
      false,
      [KEY_USAGE.deriveBits, KEY_USAGE.deriveKey],
    );
  }

  /**
   * Given some key material and some random salt
   * derive an AES-KW key using PBKDF2.
   */
  #getWrappingKey(keyMaterial) {
    return window.crypto.subtle.deriveKey(
      {
        name: ALGO_NAMES.PBKDF2,
        salt: this.#salt,
        iterations: 100_000,
        hash: ALGO_NAMES.SHA_256,
      },
      keyMaterial,
      { name: ALGO_NAMES.AES_KW, length: 256 },
      true,
      [KEY_USAGE.wrapKey, KEY_USAGE.unwrapKey],
    );
  }

  /**
   * Wrap the given key.
   */
  async wrapKey(keyToWrap, plaintext) {
    const keyMaterial = await this.#createKeyMaterial(plaintext);
    const wrappingKey = await this.#getWrappingKey(keyMaterial);

    const wrappedKey = await window.crypto.subtle.wrapKey(KEY_FORMAT.raw, keyToWrap, wrappingKey, ALGO_NAMES.AES_KW);
    return { wrappedKey, wrappingKey};
  }

  async unwrapKey(keyToUnwrap, wrappingKey) {
    return window.crypto.subtle.unwrapKey(
      KEY_FORMAT.raw,
      keyToUnwrap,
      wrappingKey,
      ALGO_NAMES.AES_KW,
      { name: ALGO_NAMES.AES_GCM, length: 256 },
      true,
      [KEY_USAGE.encrypt, KEY_USAGE.decrypt],
    );
  }
}