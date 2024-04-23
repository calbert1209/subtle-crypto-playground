import { TextCoding } from "./utilities/text-coding.js";
import { Utils } from "./utilities/index.js";
import { AesKw } from "./algorithms/aes-kw.js";
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
  const cipherText = await window.crypto.subtle.encrypt({name: ALGO_NAMES.AES_GCM, iv}, keyToWrap, tc.toArrayBuffer(secret));
  const cipherObject = {cipherText: Utils.toHexString(cipherText), iv: Utils.toHexString(iv)};

  console.log("%c ::: encrypted secret ::: \n", 'background-color: red;color:white;', cipherObject);

  await Utils.logAESKey("keyToWrap",keyToWrap)
  const aesKw = new AesKw(tc);
  const {wrappedKey, wrappingKey} = await aesKw.wrapKey(keyToWrap, password);
  console.log("%c ::: wrapped key ::: \n", "background-color: blue;color:white;", Utils.toHexString(wrappedKey));

  await Utils.logAESKey("wrappingKey",wrappingKey);
  const unwrapKey = await aesKw.unwrapKey(wrappedKey, wrappingKey);
  await Utils.logAESKey("unwrapKey",unwrapKey);

  const decrypted = await window.crypto.subtle.decrypt({name: ALGO_NAMES.AES_GCM, iv}, unwrapKey, cipherText);
  console.log("%c ::: wrapped key ::: \n", "background-color: green;color:white;", tc.fromArrayBuffer(decrypted));
})();