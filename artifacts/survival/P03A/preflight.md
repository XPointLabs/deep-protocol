# P03A preflight

Status: design and red-vector phase. Human owner: Mr. X.

## Exact pins

- accepted P03 evidence commit:
  `90e306ebf9d4ce722b95f128f5ff4bebcaddcde3`;
- P03 package manifest SHA-256:
  `87b6bafd6f3f065a720f078cee3cbad41b76492fa2c2bceb607da1ddb32b7b77`;
- P03 work-package report SHA-256:
  `df5ca700aac035a22857246957c373b61888a92ffd8a0706df16fa530ebea100`;
- P01 observer/collusion matrix SHA-256:
  `ffcfe4e6df8bbd63b04c1c590e5a47935b8e7504a4c39cf1256b322aeea5a4df`;
- P01 producer contract SHA-256:
  `ec67df8a697a3527fe1875789e64566d109ab422272946b98af2f8d9d6312063`;
- P03A task prompt SHA-256:
  `02cec87cb749283bb1ac4e128a8985c497bae23572ed9a43a0f4bdfcfa1cf8fa`.

Branch `survival/w01-p03a-compat-envelope` was created from the exact accepted P03 evidence
commit. No production default, runtime registration, package publication, network access or
deployment is authorized by this work package.

## Crypto-adapter preflight

`SodiumSessionProtocolCrypto.EncryptForRecipient` uses a sealed box, but the sender secret is used
only to derive a public identifier which is placed inside the recipient-encrypted plaintext. The
claimed sender is not signed or otherwise cryptographically authenticated by that construction.
`SodiumOnionRequestCrypto` provides anonymous hop/destination sealed-box encryption and does not
authenticate an application sender.

Neither adapter therefore satisfies the combined P03A requirement of recipient confidentiality
and cryptographic sender authentication revealed only after recipient decryption. P03A may define
the production interface and deterministic test contract, but a production implementation and
runtime activation remain BLOCKED.

