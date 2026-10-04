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

The retained counterparts `CompleteRetainedOneTimeGenesisAsync` and
`AuthorRetainedOneTimeGenesisAsync` follow
[DR-0091](../../docs/survival-program/decisions/DR-0091-did2-owned-one-time-custody.md).
They require authenticated exact retained issuance and current authority, never
an old-clock switch or predecessor. Shared's typed internal owner retains exact
invitation/ciphertext and verified commit in its single current journal. This
is a connected source target, not shipping/UI export or installed qualification.
The artifact-specific
`AuthorOneTimeGenesisRequestAsync` now signs the key-free V4 request under
[DR-0089](../../docs/survival-program/decisions/DR-0089-did2-one-time-publication-coordination.md).
It snapshots ciphertext/public locator from the disposable candidate and owned
device before callbacks. Witnesses receive neither invitation nor key; changing
the locator invalidates the publisher signature. Threshold issuance and node
claim have connected local coverage, not shipping custody or device evidence.
Do not expose QR/UI or dispatch from a shipping client before exact protected
intent/winner custody. Matched provisioning/packages and Windows/Android
evidence remain unfinished. Status and
matching commits belong to [NEXT-SPRINT](../../docs/NEXT-SPRINT.md).
