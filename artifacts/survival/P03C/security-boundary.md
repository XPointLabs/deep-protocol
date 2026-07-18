# P03C security boundary

Status: contract implemented; production runtime BLOCKED. Human owner: Mr. X.

Enforced by the contract:

- contact-scoped discovery only; no open-discovery type/default;
- 32-byte caller-provided contact secret and 16-byte rotating hint adapter boundary;
- bounded current/previous/future candidate periods;
- no clear stable identity in fixed advertisement or managed frame headers;
- exact canonical initiator/responder transcript and expected peer passed to the AKE adapter;
- bundle version, period, hop-local attempt, simultaneous-open token and resume counter are bound;
- peer identity/key returned only after adapter success and replay acceptance;
- deterministic simultaneous-open role resolution and fail-closed lifecycle;
- no production implementation of `INearbyAuthenticatedKeyExchange`.

Not claimed: forward secrecy, PCS, deniability, global anonymity, radio unlinkability, open
discovery safety, background availability or BLE permission behavior. Unknown scanners still see
Deep-shaped fixed-length emissions, bundle version, radio timing/location/signal metadata and
within-period hint repetition.

Production blockers: approved established AKE and external review; contact-secret lifecycle;
durable replay/resumption state; cross-language vectors; P12/P13 mobile/Windows E2E. Session sealed
boxes and onion crypto are not accepted substitutes.

No production credential, seed phrase, network service, Docker deployment, registry or Git remote
was accessed or changed.
