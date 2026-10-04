# Owned DID2 one-time object

Owner: Mr. X. Local API mapping for
[DR-0088](../../docs/survival-program/decisions/DR-0088-did2-owned-one-time-contact-object.md);
wire/AEAD semantics belong only to
[CONTACT-AND-GROUP §6](../../docs/architecture/CONTACT-AND-GROUP-PROTOCOL-V1.md#6-permanent-deep-id-resolution-and-one-time-invitation).
This is not a shipping/export or publication runbook.

`DeepIdV2ContactRouteAuthor.CompleteOneTimeGenesisAsync` requires the actual
current authorization/network/time, owned publisher and signed genesis
threshold. It completes the existing route with a kind-2 signed invite. Do not
use reusable completion followed by a usage-limit edit.

`DeepIdV2ContactObjectAuthor.AuthorOneTimeGenesisAsync` requires that exact
verified route and current signed device prekey descriptors. It uses the same
signed bundle/support author as reusable objects, then creates an independent
invitation and encrypted object. It takes no permanent resolver-read secret,
caller clock, caller key, raw bundle or generic signing callback.

The disposable `AuthoredDeepIdV2OneTimeContactObject` is a local candidate.
`ExactInvitation` exports a secret-bearing caller-owned copy, not a public
coordination field. Keep every retained copy in account-owned protected custody;
never log it, attach it to evidence or send it to witnesses/Registry. Dispose
clears the candidate's owned invitation/object/locator buffers; callers must
clear their own exports. `Closure` is parsed signed data, not a freshness,
publication, consent, grant, ACK or redemption capability.

`RestoreOneTimeAsync` independently authenticates exact protected DCR1,
invitation network/hash/expiry, retained plaintext and the current signed route
and identity/support. It rechecks authority/time after callbacks. Lost response
or restart must adopt the exact retained winner, never regenerate invitation
ID, locator, key, bundle or nonce. Restore does not provision missing custody.

No shipping client is connected here. The account-owned journal still needs
an explicit bounded one-time intent/commit lifecycle; current V3 publication
coordination is permanent-only and lacks the key-free signed invitation
commitment. Do not dispatch this candidate through that envelope or expose it
to QR/UI before exact custody. Matched Registry/witness issuance, selected-node
publication/claim and Windows/Android evidence remain unfinished. Status and
matching commits belong to [NEXT-SPRINT](../../docs/NEXT-SPRINT.md).
