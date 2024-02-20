// cSpell:ignore Oeap, oaep

import { TextCoding } from "../utilities/text-coding.js";
import { Utils } from "../utilities/index.js";
import { Ecdh } from "../algorithms/ecdh.js";
import { Aes } from "../algorithms/aes.js";

export async function ecdhRoundTrip() {
  console.log(
    "\n%c |::|:: ECDH ROUNDTRIP ::|::| \n",
    "color: white; background-color: tomato"
  );

  const plaintext = "I am not a cryptographer.";
  console.log("plaintext", plaintext);

  const myEcdh = await Ecdh.create(new Aes(new TextCoding()));
  await Utils.logECDHKey("mine: ", myEcdh.publicKey);

  const theirEcdh = await Ecdh.create(new Aes(new TextCoding()));
  await Utils.logECDHKey("theirs: ", theirEcdh.publicKey);

  const { cipherText, iv } = await theirEcdh.encrypt(
    myEcdh.publicKey,
    plaintext
  );
  console.log(
    `::: encrypted :::\n- cipherText: ${Utils.toHexString(
      cipherText
    )}\n- iv: ${Utils.toHexString(iv)}`
  );

  const decrypted = await myEcdh.decrypt(theirEcdh.publicKey, iv, cipherText);
  console.log(`::: decrypted :::\n- ${decrypted}`);
}
