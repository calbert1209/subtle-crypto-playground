// cSpell:ignore Oeap, oaep

import { TextCoding } from "../utilities/text-coding.js";
import { Utils } from "../utilities/index.js";
import { RsaOeap } from "../algorithms/rsa-oeap.js";

export async function rsaOeapRoundtrip() {
  console.log(
    "\n%c |::|:: RSA-OEAP ROUNDTRIP ::|::| \n",
    "color: white; background-color: Goldenrod"
  );

  const plaintext = "I am not a cryptographer.";
  console.log("plaintext", plaintext);

  const rsaOeapKey = await RsaOeap.generateKey();
  const rsaOeap = new RsaOeap(new TextCoding());

  console.log("RSA OAEP key", rsaOeapKey);

  try {
    await rsaOeap.encrypt(rsaOeapKey.privateKey, plaintext);
  } catch (e) {
    console.warn("whoops, can't encrypt with a private key!\n", e);
  }
  const cipherText = await rsaOeap.encrypt(rsaOeapKey.publicKey, plaintext);
  console.log("cipherText", Utils.toHexString(cipherText));

  try {
    await rsaOeap.decrypt(rsaOeapKey.publicKey, cipherText);
  } catch (e) {
    console.warn("whoops, can't decrypt with the public key!\n", e);
  }

  const decrypted = await rsaOeap.decrypt(rsaOeapKey.privateKey, cipherText);
  console.log("decrypted", decrypted);
}
