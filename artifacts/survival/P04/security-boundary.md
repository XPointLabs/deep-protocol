# P04 security boundary

Status: corrected contract implemented; production runtime BLOCKED. Human owner: Mr. X.

Enforced by the contract:

- strict policy V1: three distinct-of-five offline roots authorize a three-key online delegation;
- two distinct active online signers authorize bridge and membership statements;
- offline and online descriptors use distinct IDs and distinct 32-byte public keys;
- public keys come from accepted genesis/delegation canonical bytes, not ambient key lookup;
- fixed 16-byte signature-domain tags for update, membership, bridge, reward, billing, genesis,
  delegation, revocation and fork records;
- SHA-256 is the fixed canonical hash for LKG, previous-hash, delegation identity and fork evidence;
- authority and content LKG chains require exact next sequence and previous hash; overflow fails;
- active delegation is time/protocol checked, non-revoked and pinned to authority LKG;
- bridge fork witness binds domain, sequence, ancestry and the candidate hash;
- bridge discovery exposes public entry contacts, not full core/storage membership;
- self-hosted genesis is independently canonical and requires its own three-root quorum.

Not claimed: authenticity of an unpinned genesis presented by an attacker, endpoint secrecy,
traffic-analysis resistance, anonymity of public bridge contacts, automatic fork resolution,
durable rollback protection, production key custody, signature implementation security or
cross-language crypto parity.

Production blockers: approved signature adapter and key algorithm profile; trusted genesis
pin/import UX; durable atomic LKG/revocation/equivocation state; live key ceremony; P06/P07
registry/client integration; external review and cross-language vectors.

No production credential, UAT seed phrase, network service, Docker deployment, registry or Git
remote was accessed or changed.
