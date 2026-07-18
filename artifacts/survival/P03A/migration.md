# P03A migration and rollback

Default runtime behavior is unchanged because P03A has no production crypto implementation or
registration.

Future activation requires Mr. X to approve:

1. an externally reviewed production crypto adapter and its upstream vectors;
2. durable replay storage and capability lifecycle dependencies;
3. the bounded legacy read/write window and minimum safe negotiated version;
4. a release-specific observer and collusion review;
5. downstream storage/client E2E evidence.

Rollback removes the P03A feature from new negotiation offers and stops new authenticated-envelope
writes. It must retain separately readable legacy and P03A state. Authentication, replay,
downgrade or capability failures must never trigger clear DPE1, raw Session-ID lookup or direct
storage addressing.

