namespace Deep.Protocol.DeepExtension.MailboxCapabilities;

public static class MailboxReceiptVerifier
{
    public static VerifiedMailboxDurableQuorum VerifyDurableQuorum(
        ReadOnlySpan<byte> encoded,
        IMailboxReceiptCrypto crypto)
    {
        ArgumentNullException.ThrowIfNull(crypto);
        var receipt = MailboxReceiptCodec.DecodeDurableQuorum(encoded, crypto);
        VerifyReplica(receipt.FirstReplica, crypto);
        VerifyReplica(receipt.SecondReplica, crypto);

        if (receipt.FirstReplica.ReplicaId.Span.SequenceEqual(
            receipt.SecondReplica.ReplicaId.Span))
        {
            throw Error(
                MailboxReceiptError.DuplicateReplica,
                "A durable quorum requires two independent replica identifiers.");
        }

        if (receipt.FirstReplica.Status != MailboxReceiptStatus.Durable ||
            receipt.SecondReplica.Status != MailboxReceiptStatus.Durable)
        {
            throw Error(
                MailboxReceiptError.NotDurable,
                "Accepted receipts do not establish durable quorum.");
        }

        if (!StatementsAgree(receipt.FirstReplica, receipt.SecondReplica))
        {
            throw Error(
                MailboxReceiptError.ReplicaDisagreement,
                "Replica statements disagree on the durable mailbox result.");
        }

        var coordinatorSigningBytes = MailboxReceiptCodec.GetQuorumSigningBytes(receipt, crypto);
        if (!crypto.VerifyCoordinator(
            receipt.CoordinatorId.Span,
            coordinatorSigningBytes,
            receipt.Signature.Span))
        {
            throw Error(
                MailboxReceiptError.InvalidCoordinatorSignature,
                "The coordinator signature is invalid.");
        }

        return new VerifiedMailboxDurableQuorum(
            receipt.FirstReplica.Cursor,
            receipt.FirstReplica.IsTombstone,
            [receipt.FirstReplica, receipt.SecondReplica],
            receipt);
    }

    public static MailboxCoordinatorEquivocationEvidence CreateCoordinatorEquivocationEvidence(
        ReadOnlySpan<byte> firstStatement,
        ReadOnlySpan<byte> secondStatement,
        IMailboxReceiptCrypto crypto)
    {
        var first = VerifyDurableQuorum(firstStatement, crypto).CoordinatorReceipt;
        var second = VerifyDurableQuorum(secondStatement, crypto).CoordinatorReceipt;
        if (!first.CoordinatorId.Span.SequenceEqual(second.CoordinatorId.Span) ||
            first.CoordinatorSequence != second.CoordinatorSequence ||
            firstStatement.SequenceEqual(secondStatement))
        {
            throw Error(
                MailboxReceiptError.NotEquivocation,
                "The two verified statements do not prove coordinator equivocation.");
        }

        return new MailboxCoordinatorEquivocationEvidence(
            first.CoordinatorId.ToArray(),
            first.CoordinatorSequence,
            firstStatement.ToArray(),
            secondStatement.ToArray());
    }

    private static void VerifyReplica(
        MailboxReplicaReceipt receipt,
        IMailboxReceiptCrypto crypto)
    {
        var signingBytes = MailboxReceiptCodec.GetReplicaSigningBytes(receipt);
        if (!crypto.VerifyReplica(
            receipt.ReplicaId.Span,
            signingBytes,
            receipt.Signature.Span))
        {
            throw Error(
                MailboxReceiptError.InvalidReplicaSignature,
                "A replica signature is invalid.");
        }
    }

    private static bool StatementsAgree(
        MailboxReplicaReceipt first,
        MailboxReplicaReceipt second) =>
        first.OperationId.Span.SequenceEqual(second.OperationId.Span) &&
        first.Generation == second.Generation &&
        first.Cursor == second.Cursor &&
        first.IsTombstone == second.IsTombstone &&
        first.PayloadDigest.Span.SequenceEqual(second.PayloadDigest.Span);

    private static MailboxReceiptException Error(
        MailboxReceiptError error,
        string message) =>
        new(error, message);
}
