export class Utils {
  static toHexString(buffer) {
    return Array.from(new Uint8Array(buffer))
      .map((n) => n.toString("16"))
      .join("");
  }

  static fromHex(hexString) {
    const keyBits = [];
    for (let i = 0; i < hexString.length; i += 2) {
      const slice = hexString.substring(i, i + 2);
      const intValue = parseInt(`0x${slice}`, 16);
      keyBits.push(intValue);
    }

    return new Uint8Array(keyBits);
  }

  static async exportKeyAsBuffer(key, tc) {
    const exportedKey = await Utils.exportKey(key);
    const json = JSON.stringify(exportedKey);
    return tc.toArrayBuffer(json);
  }

  static async exportKeyAsHex(key, tc) {
    const buffer = await Utils.exportKeyAsBuffer(key, tc);
    return Utils.toHexString(buffer);
  }

  static async logECDHKey(memo, key) {
    const exported = await Utils.exportKey(key);
    console.log(`${memo}\n- x: ${exported.x}\n- y: ${exported.y}`);
  }

  static async logAESKey(memo, key) {
    const exported = await Utils.exportKey(key);
    console.log(`${memo}\n- ${exported.k}`);
  }

  static logAesEncryptionResult(ct, iv, kHex) {
    const lines = [
      "::: encrypted :::",
      `ct: ${Utils.toHexString(ct)}`,
      `iv: ${Utils.toHexString(iv)}`,
      `key: ${kHex}`,
    ];
    console.log(lines.join("\n"));
  }

  static paginate(text, chars) {
    const pages = [];
    for (let i = 0; i < text.length; i += chars) {
      pages.push(text.slice(i, i + chars));
    }
    return pages;
  }

  static logPgpLikeResults(ct, iv, k, keyIv) {
    const lines = [
      "::: encrypted :::",
      `ct:    ${Utils.toHexString(ct)}`,
      `iv:    ${Utils.toHexString(iv)}`,
      '\n',
      `key:   ${Utils.paginate(Utils.toHexString(k), 48).join("\n       ")}`,
      `keyIv: ${Utils.toHexString(keyIv)}`,
    ];
    console.log(lines.join("\n"));
  }

  static async exportKey(key) {
    return window.crypto.subtle.exportKey("jwk", key);
  }
}
