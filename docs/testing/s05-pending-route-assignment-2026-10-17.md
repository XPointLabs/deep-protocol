# S05 pending genesis assignment

Source correction under accepted DR-0122; no wire, signature domain, ranking,
public API, persistence generation, compatibility reader or consumer reset.
Packaged consumers still need their ordinary reviewed rebuild/repin qualification.

A real CLI publication failed after ordinary view renewal. Proposal verification
already resolved its exact logical assignment through verified retained history,
but genesis threshold authoring used the terminal PMT. The static graph also
required the genesis issuance view to equal the assignment snapshot's view.
The author now binds the proposal's exact assignment through the same closed
eligibility owner as verification/completion. The graph keeps its creation-window,
reference, replica, sealing and timed-intersection checks; actual issuance view,
head, witness keys and signed/currentness checks remain independently mandatory.

Shared regression `Did2PendingRoute_ThresholdCompletesExactProposalAcrossViewButRejectsChangedEpoch`
uses a real signed account/history and encrypted cold reopen. Before correction:
focused01 retained1FAIL/1PASS. After assignment binding alone: focused02 retained
1FAIL/4PASS, exposing the remaining static view-equality condition. Corrected
focused03:5PASS/native0/0skip, including logical-assignment scenarios. It checks
unchanged proposal/assignment, current issuance, rejection of a fully signed old
issuance as new threshold authority and refusal after a genuine epoch change.

The existing mutated-XNV graph negative remains rejected at Closure, now by
the exact XSS-to-XRC reference rather than obsolete PMT/view equality. No
negative case or frozen vector bytes were removed.

This is not connected CLI delivery, a full/package gate, device acceptance or
release qualification. Single semantics owner: CONTACT-RESOLVER §3.6 in the
superproject; no second protocol specification is introduced here.
