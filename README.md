# Deep Protocol

Production protocol libraries for Deep messaging, membership routes and self-hosted profile
carriers. The repository targets .NET 10 and is a clean-break implementation: production packages
contain no compatibility shims, aliases or fallback runtime paths.

## Start here

- [`AGENTS.md`](AGENTS.md) defines the production boundary and required checks.
- [`docs/protocol-surface.md`](docs/protocol-surface.md) lists the implemented protocol surface.
- [`docs/unsupported-or-unspecified.md`](docs/unsupported-or-unspecified.md) records surfaces that
  must not be wired into production.
- The extension specifications in [`docs/`](docs/) are the repository-level contracts.
- The superproject's `docs/survival-program/releases/v3.0.0/specs/` contains the frozen DNP1
  registries, schemas and ownership rules.

## Production projects

- `Deep.Protocol`: canonical codecs and cryptographic protocol behavior.
- `Deep.Protocol.MembershipRoutes`: signed membership and mailbox route contracts.
- `Deep.Protocol.ProfileCarrier`: bounded self-hosted profile carrier contracts.

The former `Deep.Protocol.Native` dark identity path has been clean-break promoted into
`Deep.Protocol.Identity` and removed. The pre-user Session compatibility corpus has
also been removed; Git history is sufficient if an old implementation must be audited.

The DID2 publication consumer and closed owned commit verifier follow the
superproject's DR-0039/DR-0040 decisions. Two-replica signed commit evidence
does not renew an expired publication request or establish mailbox authority,
contact consent or physical delivery. Shipping/private transport, consumer
API/evidence repins and device gates remain required.
DR-0041 adds descriptor-bound parsed bootstrap and independently verified DID2
permanent contact reads. A parsed candidate is not current identity authority;
closed read evidence does not accept a contact or establish message delivery.
DR-0042 distinguishes signed route issuance anchors from independently current
identity: unrelated directory admission does not invalidate retained contacts.
New issuance and publication dispatch still require current authority.
Exact issued-head coordination follows
[DR75](../docs/survival-program/decisions/DR-0075-did2-issued-head-response-custody.md).
Request and response generations are independently closed; every Registry,
XNode and client consumer must rebuild/repin together. No retired response reader
or historical-currentness flag is supported. Matched deployment is still gated.
Route-time rejection diagnostics use only closed artifact and boundary labels,
never interval values, identities or bytes. This changes no wire, public API,
protected format or complete-interval predicate, and requires no account reset.
Downstream diagnostic clients must rebuild against the committed source; a
label is failure classification only, not authority or delivery evidence.
Private node-to-coordinator transport admission follows
[DR-0048](../docs/survival-program/decisions/DR-0048-private-contact-coordination-peer-authentication.md).
`ContactV2.ContactCoordinationPeerAuthentication` binds the existing node key
to the exact target/network/body and transport time. It grants no DID2, network,
witness, placement or ACK capability. Verified carrier composition and package
API/vector repins remain activation gates.

## Verify

```powershell
dotnet restore Deep.Protocol.slnx
dotnet build Deep.Protocol.slnx --no-restore
dotnet test Deep.Protocol.slnx --no-build
./eng/Test-ProductionProtocolGraph.ps1 -Configuration Debug
```
