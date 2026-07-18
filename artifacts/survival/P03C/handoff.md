# P03C handoff

Branch `survival/w01-p03c-nearby-handshake`.

- Final P03B GO base: `b1d74e5229137928bf9c70daa0dc133350a98c34`.
- ADR/preflight: `389d7f09b2c6b9a5d61ffc207efa93a3f1d9c95f`.
- Red vectors: `d10c6a255686b006b7235de902c790fb48dbdcb6`.
- Initial green: `86581beb69ce0ed8084a31e4aa4e08ac7675c60c`.
- Corrective red: `4f9d28b658823f1d634e469c017c56f155758ae2`.
- Corrected green: `8d77e833b595aae8936d9b9d1b3f6ef76180a426`.
- Final provenance red: `b095c81a9d55212a0a5c9995aea4218c5da69d3c`.
- Final corrected green: `261c77658c8ff1f51ba45116ca8d938b1336eaa9`.
- Package: `0.3.0-p03c.261c776`.

P12/P13 receive `NearbyHandshakeProtocol`, `NearbyHandshakeCodec`,
`NearbyHandshakeLifecycle`, `NearbyHandshakeBinding`, `NearbyRendezvousPolicy`,
`INearbyAuthenticatedKeyExchange` and `INearbyHandshakeReplayGuard`.

They must supply radio/permission/background behavior and must not implement cryptography behind
the adapter until an established AKE is selected and reviewed. `TransportAttemptId` is hop-local
and maps to the opaque bundle attempt, never the end-to-end dedup identifier. Runtime remains
blocked; no push, publish or deployment occurred.
