import { TextCoding } from "../utilities/text-coding.js";
import { Utils } from "../utilities/index.js";
import { Ecdh } from "../algorithms/ecdh.js";
import { Aes } from "../algorithms/aes.js";

export async function pgpLikeRoundtrip() {
  console.log(
    "\n%c |::|:: PGP-LIKE ROUNDTRIP ::|::| \n",
    "color: white; background-color: orchid"
  );

  const plainText = "I am not a cryptographer.";
  console.log("plaintext", plainText);

  const tc = new TextCoding();
  const myEcdh = await Ecdh.create(new Aes(tc));
  await Utils.logECDHKey("mine key: ", myEcdh.publicKey);

  const theirEcdh = await Ecdh.create(new Aes(tc));
  await Utils.logECDHKey("their key: ", theirEcdh.publicKey);

  const aes = new Aes(tc);
  const aesCtrKey = await aes.generateKey();
  const { cipherText, iv } = await aes.encrypt(aesCtrKey, plainText);

  const keyAsBuffer = await Utils.exportKeyAsBuffer(aesCtrKey, tc);
  const { cipherText: encryptedKey, iv: keyIv } = await myEcdh.encrypt(
    theirEcdh.publicKey,
    keyAsBuffer
  );
  Utils.logPgpLikeResults(cipherText, iv, encryptedKey, keyIv);

  const decryptedKey = await theirEcdh.decrypt(myEcdh.publicKey, keyIv, encryptedKey, true);
  console.log("::: decrypt key :::\n", decryptedKey);
  const importedKey = await aes.importJwtKey(tc.toArrayBuffer(decryptedKey));
  console.log("aes key:", importedKey);

  const decryptedText = await aes.decrypt(importedKey, iv, cipherText);
  console.log("::: decrypt cipher text :::\n", decryptedText);
}
