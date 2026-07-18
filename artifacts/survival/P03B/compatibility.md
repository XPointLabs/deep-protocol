# P03B compatibility and rollback

`MCP1`, `MRR1`, `MQR1` and `MBE1` are Deep extension formats. They do not edit Session protobufs,
existing Session wire behavior or P03/P03A golden vectors. Old readers reject the distinct
magic/version; new readers require exact version, domain and canonical lengths.

Mixed-version compatibility is explicit only:

- strict V1 is the default marker;
- a legacy mirror is accepted only with overlap lifecycle, a finite overlap deadline and an
  explicit decode-policy opt-in;
- no fallback converts deposit/retrieve/placement values or uses a raw Session ID;
- accepted status never upgrades itself to durable;
- free admission does not weaken capability, receipt or replay verification.

Rollback stops issuing new V1 values and disables feature negotiation/registration. Existing
receipts and tombstones remain verifiable and retained as evidence. A bounded legacy mirror may
continue only until its precommitted overlap deadline. Rollback must not delete durable receipts,
reset generations/cursors or silently reuse values across domains.

Runtime remains blocked, so this package changes no production default and requires no active
rollback action.
