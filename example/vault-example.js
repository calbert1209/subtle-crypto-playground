import { TextCoding } from "./utilities/text-coding.js";
import { Utils } from "./utilities/index.js";
import { AesKw } from "./algorithms/aes-kw.js";
import { Aes } from "./algorithms/aes.js";
import { ALGO_NAMES, KEY_USAGE } from "./utilities/constants.js";

/*
Wrap the given key.
*/
async function wrapCryptoKey(aesKw, keyToWrap) {
  // get the key encryption key
  const password = window.prompt("Enter your password");
  return aesKw.wrapKey(keyToWrap, password);
}

/*
Generate an encrypt/decrypt secret key,
then wrap it.
*/
(async function main() {
  const secret = window.prompt("Enter your secret");
  const password = window.prompt("Enter your password");
  const tc = new TextCoding();
  const keyToWrap = await window.crypto.subtle.generateKey(
    {
      name: ALGO_NAMES.AES_GCM,
      length: 256,
    },
    true,
    [KEY_USAGE.encrypt, KEY_USAGE.decrypt]
  );
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const cipherText = await window.crypto.subtle.encrypt(
    { name: ALGO_NAMES.AES_GCM, iv },
    keyToWrap,
    tc.toArrayBuffer(secret)
  );

  await Utils.logAESKey("keyToWrap", keyToWrap);
  const aesKw = new AesKw(tc);
  const { wrappedKey, wrappingKey } = await aesKw.wrapKey(keyToWrap, password);
  console.log(
    "%c ::: wrapped key ::: \n",
    "background-color: blue;color:white;",
    Utils.toHexString(wrappedKey)
  );

  const cipherObject = {
    cipherText: Utils.toHexString(cipherText),
    iv: Utils.toHexString(iv),
    key: Utils.toHexString(wrappedKey),
  };

  console.log(
    "%c ::: encrypted secret ::: \n",
    "background-color: red;color:white;",
    cipherObject
  );

  // create vault key from password
  const aes = new Aes(tc);
  const { salt: vKeySalt, key: vKey } = await aes.deriveKeyFromPassword(
    password
  );

  // encrypt vault
  const cipherJson = JSON.stringify({ entries: [cipherObject] });
  const vIv = window.crypto.getRandomValues(new Uint8Array(12));
  const vCipherText = await window.crypto.subtle.encrypt(
    { name: ALGO_NAMES.AES_GCM, iv: vIv },
    vKey,
    tc.toArrayBuffer(cipherJson)
  );
  const vCipherObject = {
    ct: Utils.toHexString(vCipherText),
    iv: Utils.toHexString(vIv),
    salt: Utils.toHexString(vKeySalt),
  };

  console.log(
    "%c ::: encrypted vault ::: \n",
    "background-color: orange;color:white;",
    vCipherObject
  );

  await Utils.logAESKey("wrappingKey", wrappingKey);
  const unwrapKey = await aesKw.unwrapKey(wrappedKey, wrappingKey);
  await Utils.logAESKey("unwrappedKey", unwrapKey);

  const decrypted = await window.crypto.subtle.decrypt(
    { name: ALGO_NAMES.AES_GCM, iv },
    unwrapKey,
    cipherText
  );
  console.log(
    "%c ::: decrypted text ::: \n",
    "background-color: green;color:white;",
    tc.fromArrayBuffer(decrypted)
  );
})();
