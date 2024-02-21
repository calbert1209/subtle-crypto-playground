// cSpell:ignore Oeap, oaep

import { aesRoundTrip } from "./round-trips/aes-ctr-roundtrip.js";
import { ecdhRoundTrip } from "./round-trips/ecdh-roundtrip.js";
import { pgpLikeRoundtrip } from "./round-trips/pgp-like-roundtrip.js";
import { rsaOeapRoundtrip } from "./round-trips/rsa-oeap-roundtrip.js";

ecdhRoundTrip().then(rsaOeapRoundtrip).then(aesRoundTrip).then(pgpLikeRoundtrip);
