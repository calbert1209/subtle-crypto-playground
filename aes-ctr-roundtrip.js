import { TextCoding } from "./text-coding.js";
import { Utils } from "./utils.js";
import { Aes } from "./aes.js";

export async function aesRoundTrip() {
  console.log(
    "\n%c |::|:: AES-CTR ROUNDTRIP ::|::| \n",
    "color: white; background-color: cadetBlue"
  );

  const plainText = "Hotdogs are delicious.";
  console.log("plain text: ", plainText);

  const tc = new TextCoding();
  const aes = new Aes(tc);
  const aesCtrKey = await aes.generateKey();

  const { cipherText, iv } = await aes.encrypt(aesCtrKey, plainText);

  const keyAsHex = await Utils.exportKeyAsHex(aesCtrKey, tc);
  Utils.logAesEncryptionResult(cipherText, iv, keyAsHex);

  const uint8Array = Utils.fromHex(keyAsHex);
  const importedKey = await aes.importJwtKey(uint8Array);
  console.log("::: imported key :::\n", importedKey);

  const decrypted = await aes.decrypt(importedKey, iv, cipherText);
  console.log(`::: decrypted :::\n  ${decrypted}`);
}
