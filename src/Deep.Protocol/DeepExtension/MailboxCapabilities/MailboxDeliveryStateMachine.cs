namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxDeliveryStateMachine
{
    public static MailboxClientDeliveryStatus Transition(
        MailboxClientDeliveryStatus current,
        MailboxClientDeliveryStatus requested,
        MailboxDeliveryTransitionEvidence evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        if (current == requested)
        {
            return current;
        }

        if (current == MailboxClientDeliveryStatus.Accepted &&
            requested == MailboxClientDeliveryStatus.Durable &&
            evidence.DurableQuorumVerified)
        {
            return requested;
        }

        if (current == MailboxClientDeliveryStatus.Durable &&
            requested == MailboxClientDeliveryStatus.Delivered &&
            evidence.PayloadAuthenticatedAndDecrypted &&
            evidence.DurableAckTombstoneVerified)
        {
            return requested;
        }

        throw new MailboxClientException(
            MailboxClientError.InvalidDeliveryTransition,
            "Accepted is not durable, and delivered is a client-only state requiring " +
            "authenticated decryption plus a verified durable acknowledgement tombstone.");
    }
}
