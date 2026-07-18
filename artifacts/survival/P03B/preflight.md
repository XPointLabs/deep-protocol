# P03B preflight

Status: ADR and red-vector phase. Human owner: Mr. X.

## Exact pins

- base P03A evidence commit:
  `0bb1d484408b0ad673f51e67673dce1ac34b6b12`;
- P03B prompt SHA-256:
  `bfee5e57ee02ac2a46e22ef23320b7e7fa96e8420407b6a412e2740346e62413`;
- P01 observer matrix SHA-256:
  `ffcfe4e6df8bbd63b04c1c590e5a47935b8e7504a4c39cf1256b322aeea5a4df`;
- P01 producer contract SHA-256:
  `ec67df8a697a3527fe1875789e64566d109ab422272946b98af2f8d9d6312063`;
- accepted P03 report SHA-256:
  `e691516691d85b0c34850430e7f5f493615658c8577344a7d8a8293b675ee0a2`;
- P03A report SHA-256:
  `b08be0a0f7b047689356b1ade02a23abd47f53f49d16a3da13874af5e6e8f6a3`;
- P03A package manifest SHA-256:
  `6b6493677f244e07077bcfb60faf6a43b1c994946e60f8c91324e888ee7e316d`.

Branch `survival/w01-p03b-mailbox-capabilities` was created from the exact base evidence commit.
P03B defines wire and verification interfaces only. It does not implement capability generation,
lifecycle persistence, storage execution, billing, quota policy or cryptographic primitives.

