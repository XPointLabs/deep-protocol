# P03C initial review and correction map

Initial verdict: NO-GO. Counts P0=0, P1=4, P2=2, P3=0.

All findings were converted to corrective tests and code:

- fixed rendezvous and AKE domain bytes are codec-owned adapter parameters and vector inputs;
- public discovery APIs require `ContactDiscoverySecret.FromReviewedProducer`, not identity spans;
- every create/respond/complete requires bounded current/skew period policy before adapter/replay;
- binding uses the existing `OpaqueBundles.TransportAttemptId` type;
- both responder and initiator replay scopes contain the exact full canonical transcript;
- replay decisions explicitly distinguish fresh/resumption/rejected and tests enforce strict
  advancing resumption/reuse rejection.

Corrective red `4f9d28b658823f1d634e469c017c56f155758ae2`; corrected source
`8d77e833b595aae8936d9b9d1b3f6ef76180a426`. Post-correction full 147/147, focused 14/14.
Independent corrective rereview is required; runtime remains blocked.
