import { TextCoding } from "./utilities/text-coding.js";
import { Utils } from "./utilities/index.js";
import { AesKw } from "./algorithms/aes-kw.js";
import { Aes } from "./algorithms/aes.js";
import { ALGO_NAMES, KEY_USAGE } from "./utilities/constants.js";

(async function main() {
  const secret = window.prompt("Enter your secret");
  const password = window.prompt("Enter your password");
  const tc = new TextCoding();

  // create key KE to encrypt/decrypt secret
  const keyToWrap = await window.crypto.subtle.generateKey(
    {
      name: ALGO_NAMES.AES_GCM,
      length: 256,
    },
    true,
    [KEY_USAGE.encrypt, KEY_USAGE.decrypt]
  );
  await Utils.logAESKey("keyToWrap", keyToWrap);

  // encrypt secret via KE
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const cipherText = await window.crypto.subtle.encrypt(
    { name: ALGO_NAMES.AES_GCM, iv },
    keyToWrap,
    tc.toArrayBuffer(secret)
  );

  // wrap KE via AES-KW
  const aesKw = new AesKw(tc);
  const { wrappedKey, wrappingKey } = await aesKw.wrapKey(keyToWrap, password);
  console.log(
    "%c ::: wrapped key ::: \n",
    "background-color: blue;color:white;",
    Utils.toHexString(wrappedKey),
    new Uint8Array(wrappedKey)
  );

  await Utils.logAESKey("wrappingKey", wrappingKey);

  // create Entry
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

  // create vault key KV from password
  const aes = new Aes(tc);
  const { salt: vKeySalt, key: vKey } = await aes.deriveKeyFromPassword(
    password
  );

  // encrypt vault using KV
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

  // get
  const { key: vaultDecryptKey } = await aes.deriveKeyFromPassword(
    password,
    Utils.fromHex(vCipherObject.salt)
  );

  const buffer = await window.crypto.subtle.decrypt(
    {
      name: ALGO_NAMES.AES_GCM,
      iv: vIv,
    },
    vaultDecryptKey,
    Utils.fromHex(vCipherObject.ct)
  );

  const dVault = JSON.parse(tc.fromArrayBuffer(buffer));
  const [dEntry] = dVault.entries;
  const dWrappedKey = Utils.fromHex(dEntry.key);
  const dCt = Utils.fromHex(dEntry.cipherText);
  const dIv = Utils.fromHex(dEntry.iv);

  console.log("decrypt vault key", dWrappedKey);

  // const unwrapKey = await aesKw.unwrapKey(wrappedKey, wrappingKey);
  const unwrapKey = await aesKw.unwrapKey(dWrappedKey, wrappingKey);
  await Utils.logAESKey("unwrappedKey", unwrapKey);

  const decrypted = await window.crypto.subtle.decrypt(
    { name: ALGO_NAMES.AES_GCM, iv: dIv },
    unwrapKey,
    dCt
  );
  console.log(
    "%c ::: decrypted text ::: \n",
    "background-color: green;color:white;",
    tc.fromArrayBuffer(decrypted)
  );
})();
