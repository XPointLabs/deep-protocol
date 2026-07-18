# P03A focused independent review packet

Review exact source commit `a3f70363cf8aa2eef4f5a8d80be50bc638911201` and the subsequent
evidence-only commit. Do not treat the deterministic test adapter as a selected primitive.

## Required reviewer questions

1. Does any sender or recipient authentication material appear in DPB1 outer bytes or only after
   adapter open?
2. Are capability, hop-local attempt, expiry, replay, padding, feature/payload kind and both nonce
   contexts authenticated by the exact same associated-data construction on seal/open?
3. Can header/payload ciphertext or domains be swapped without authentication failure?
4. Are header and payload nonce contexts distinct and are adapter key domains caller-invariant?
5. Can tamper, wrong recipient, malformed header/DPE1, sender mismatch, replay, expiry or downgrade
   return sender data or plaintext?
6. Does any production assembly implement/register `ICompatibilityEnvelopeCrypto`, directly or
   through an existing sodium adapter?
7. Are the observer/collusion and no-forward-secrecy claims limited honestly?
8. Do package hashes, nuspec source commits, vector hash and test evidence match?

Production activation must remain NO-GO even if the contract review is GO.

