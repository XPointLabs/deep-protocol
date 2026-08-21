using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

/// <summary>Owned exact current cutover evidence. The carry input is not authority.</summary>
public sealed class CurrentCutoverRestoreInput
{
    private readonly byte[][] _records;
    private readonly byte[][] _keyIds;

    public CurrentCutoverRestoreInput(
        ReadOnlySpan<byte> dcm1,
        ReadOnlySpan<byte> dcp1,
        ReadOnlySpan<byte> dcs1,
        ReadOnlySpan<byte> dcq1,
        ReadOnlySpan<byte> dwl1,
        ReadOnlySpan<byte> dcl1,
        ReadOnlySpan<byte> dpl1,
        ReadOnlySpan<byte> dplKeyId32,
        ReadOnlySpan<byte> dwlKeyId32,
        ReadOnlySpan<byte> rrlKeyId32,
        ReadOnlySpan<byte> ribKeyId32,
        ReadOnlySpan<byte> mrlcKeyId32,
        ReadOnlySpan<byte> dxrKeyId32,
        ReadOnlySpan<byte> recoveryNonceLatchKeyId32)
    {
        var definitions = new[] { RecordDefinitions.Dcm1,RecordDefinitions.Dcp1,
            RecordDefinitions.Dcs1,RecordDefinitions.Dcq1,RecordDefinitions.Dwl1,
            RecordDefinitions.Dcl1,RecordDefinitions.Dpl1 };
        // All declared bounds and field tables are checked before retaining the snapshots.
        CanonicalGrammar.Preflight(dcm1, definitions[0]);
        CanonicalGrammar.Preflight(dcp1, definitions[1]);
        CanonicalGrammar.Preflight(dcs1, definitions[2]);
        CanonicalGrammar.Preflight(dcq1, definitions[3]);
        CanonicalGrammar.Preflight(dwl1, definitions[4]);
        CanonicalGrammar.Preflight(dcl1, definitions[5]);
        CanonicalGrammar.Preflight(dpl1, definitions[6]);
        ValidateKeyId(dplKeyId32); ValidateKeyId(dwlKeyId32); ValidateKeyId(rrlKeyId32);
        ValidateKeyId(ribKeyId32); ValidateKeyId(mrlcKeyId32); ValidateKeyId(dxrKeyId32);
        ValidateKeyId(recoveryNonceLatchKeyId32);
        var values = new[] { dcm1.ToArray(), dcp1.ToArray(), dcs1.ToArray(), dcq1.ToArray(),
            dwl1.ToArray(), dcl1.ToArray(), dpl1.ToArray() };
        foreach (var value in values.Select((bytes, index) => (bytes, index)))
            CanonicalGrammar.Preflight(value.bytes, definitions[value.index]);
        _records = values;
        _keyIds = new[] { dplKeyId32.ToArray(),dwlKeyId32.ToArray(),rrlKeyId32.ToArray(),
            ribKeyId32.ToArray(),mrlcKeyId32.ToArray(),dxrKeyId32.ToArray(),
            recoveryNonceLatchKeyId32.ToArray() };

        static void ValidateKeyId(ReadOnlySpan<byte> keyId)
        {
            if (keyId.Length != 32 || CanonicalGrammar.IsZero(keyId))
                throw new RecordException(RecordError.InvalidField,
                    "A current cutover protected-state key ID is invalid.");
        }
    }

    internal ReadOnlyMemory<byte> Record(int index) => _records[index];
    internal ReadOnlyMemory<byte> KeyId(int index) => _keyIds[index];
    public bool NoAuthorityClaim => true;
}

/// <summary>Restores one exact current cutover/DRS source relative to sealed identity and root facts.</summary>
public sealed class CurrentCutoverVerifier
{
    public async ValueTask<CurrentCutoverRelative> RestoreCurrentAsync(
        CurrentCutoverRestoreInput input,
        VerifiedIdentityRelative identity,
        ReleaseRootRestoreRelative releaseRoot,
        ComponentKind expectedComponentKind,
        ulong transactionTimeUnixSeconds,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(releaseRoot);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        if (!Enum.IsDefined(expectedComponentKind) || expectedComponentKind == 0 ||
            transactionTimeUnixSeconds == 0 || !releaseRoot.IsUsable || identity.IsTerminal || identity.ForkLatched)
            Invalid("The current cutover restore context is unusable.");
        cancellationToken.ThrowIfCancellationRequested();

        var dcm = Decode(input, 0, RecordDefinitions.Dcm1);
        var dcp = Decode(input, 1, RecordDefinitions.Dcp1);
        var dcs = Decode(input, 2, RecordDefinitions.Dcs1);
        var dcq = Decode(input, 3, RecordDefinitions.Dcq1);
        var dwl = Decode(input, 4, RecordDefinitions.Dwl1);
        var dcl = Decode(input, 5, RecordDefinitions.Dcl1);
        var dpl = Decode(input, 6, RecordDefinitions.Dpl1);
        var dcmRef = Ref(ArtifactType.Dcm1, dcm);
        var dcpRef = Ref(ArtifactType.Dcp1, dcp);
        var dcsRef = Ref(ArtifactType.Dcs1, dcs);
        var dcqRef = Ref(ArtifactType.Dcq1, dcq);
        var dwlRef = Ref(ArtifactType.Dwl1, dwl);
        var dclRef = Ref(ArtifactType.Dcl1, dcl);
        var dplRef = Ref(ArtifactType.Dpl1, dpl);

        // Bind every fixed source and HMAC selector before the first callback.
        var account = identity.Account;
        var drs = identity.Revocations.Snapshot;
        Equal(dcm.FieldSpan(1), account.Certificate.NetworkId.Span, "DCM/account network mismatch.");
        Equal(dcm.FieldSpan(5), Ref(ArtifactType.Dpa1, account.Certificate.Record), "DCM account mismatch.");
        if (Scalars.UInt64(dcm.FieldSpan(4)) != account.Certificate.AccountGeneration ||
            Scalars.UInt64(dcm.FieldSpan(6)) != drs.Revision ||
            Scalars.UInt64(dcm.FieldSpan(7)) != drs.EntryCount)
            Invalid("DCM identity/DRS scalar mismatch.");
        Equal(dcm.FieldSpan(8), drs.CurrentHead.Span, "DCM DRS head mismatch.");
        Equal(dcm.FieldSpan(9), Ref(ArtifactType.Drs1, drs.Record), "DCM DRS ref mismatch.");
        Equal(dcp.FieldSpan(1), dcm.FieldSpan(1), "DCP network mismatch.");
        if (Scalars.UInt16(dcp.FieldSpan(3)) != (ushort)expectedComponentKind ||
            Scalars.UInt64(dcp.FieldSpan(6)) != account.Certificate.AccountGeneration)
            Invalid("DCP component/account mismatch.");
        Equal(dcp.FieldSpan(7), dcmRef, "DCP DCM mismatch.");
        Equal(dcp.FieldSpan(11), dcm.FieldSpan(9), "DCP DRS mismatch.");
        var subjectPayload = new byte[82];
        dcm.FieldSpan(1).CopyTo(subjectPayload);
        account.DeepAccountIdHash.Span.CopyTo(subjectPayload.AsSpan(16));
        BinaryPrimitives.WriteUInt16BigEndian(subjectPayload.AsSpan(48,2),(ushort)expectedComponentKind);
        account.Certificate.AccountRevocationHandle.Span.CopyTo(subjectPayload.AsSpan(50));
        Equal(dcp.FieldSpan(2), CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/component-subject", subjectPayload), "DCP component subject mismatch.");
        VerifyComponentRows(dcs, dcm, dcmRef, dcp, dcpRef, expectedComponentKind);
        Equal(dcq.FieldSpan(1), dcm.FieldSpan(1), "DCQ network mismatch.");
        Equal(dcq.FieldSpan(4), dcsRef, "DCQ DCS mismatch.");
        Equal(dpl.FieldSpan(1), dcm.FieldSpan(1), "DPL network mismatch.");
        if (Scalars.UInt16(dpl.FieldSpan(2)) != (ushort)expectedComponentKind ||
            Scalars.UInt64(dpl.FieldSpan(3)) != account.Certificate.AccountGeneration ||
            Scalars.UInt64(dpl.FieldSpan(5)) != Scalars.UInt64(dcm.FieldSpan(3)) ||
            dpl.FieldSpan(16)[0] != 0)
            Invalid("DPL scalar/fork state mismatch.");
        Equal(dpl.FieldSpan(4), dcm.FieldSpan(5), "DPL account mismatch.");
        Equal(dpl.FieldSpan(6), dcmRef, "DPL DCM mismatch.");
        Equal(dpl.FieldSpan(11), dcm.FieldSpan(9), "DPL DRS mismatch.");
        Equal(dpl.FieldSpan(12), dcpRef, "DPL DCP mismatch.");
        Equal(dpl.FieldSpan(13), dcsRef, "DPL DCS mismatch.");
        Equal(dpl.FieldSpan(14), dcqRef, "DPL DCQ mismatch.");
        Equal(dwl.FieldSpan(1), dcm.FieldSpan(1), "DWL network mismatch.");
        Equal(dwl.FieldSpan(8), dcsRef, "DWL DCS mismatch.");
        Equal(dwl.FieldSpan(9), dcqRef, "DWL DCQ mismatch.");
        Equal(dwl.FieldSpan(10), dclRef, "DWL DCL mismatch.");
        if (dwl.FieldSpan(12)[0] != 0 || Scalars.UInt64(dwl.FieldSpan(11)) !=
            Scalars.UInt64(dcl.FieldSpan(13)))
            Invalid("DWL lease/fork state mismatch.");
        if (releaseRoot.FreshLease is null ||
            !CanonicalGrammar.FixedEquals(releaseRoot.FreshLease.CanonicalBytes.Span, dcl.CanonicalSpan))
            Invalid("The current cutover DCL is not the sealed fresh ReleaseRoot lease.");
        var authorityHead = CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/release-root-authority-head",
            releaseRoot.AuthorityTuple.CanonicalTuple.Span);
        Equal(dcl.FieldSpan(6), authorityHead, "DCL ReleaseRoot authority head mismatch.");
        var leaseExpires = Scalars.UInt64(dcl.FieldSpan(13));
        if (transactionTimeUnixSeconds >= leaseExpires ||
            transactionTimeUnixSeconds < Scalars.UInt64(dcm.FieldSpan(14)))
            throw new RecordException(RecordError.Expired,
                "The current cutover activation/lease window is not live.");

        await VerifyHmacAsync(dpl, input.KeyId(0), hmacProvider, cancellationToken).ConfigureAwait(false);
        await VerifyHmacAsync(dwl, input.KeyId(1), hmacProvider, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();

        var reset = identity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        if (reset.IsTerminal) Invalid("The reset-control key is terminal.");
        VerifySignature(dcm.FieldSpan(18), CanonicalGrammar.GetSigningBytes(dcm,
            "Deep/Cutover/V1/manifest"), reset.CurrentEd25519PublicKey.Span);
        VerifySignature(dcm.FieldSpan(19), CanonicalGrammar.GetSigningBytes(dcm,
            "Deep/Cutover/V1/manifest"), account.Certificate.AccountEd25519PublicKey.Span);
        VerifySignature(dcp.FieldSpan(21), CanonicalGrammar.GetSigningBytes(dcp,
            "Deep/Cutover/V1/component-checkpoint"), reset.CurrentEd25519PublicKey.Span);
        VerifySignature(dcs.FieldSpan(14), CanonicalGrammar.GetSigningBytes(dcs,
            "Deep/Cutover/V1/deployment-set"), reset.CurrentEd25519PublicKey.Span);

        return new CurrentCutoverRelative(
            dcm.FieldSpan(1), dcm.FieldSpan(2), expectedComponentKind,
            account.DeepAccountIdHash.Span, account.Certificate.AccountGeneration,
            Scalars.UInt64(dcm.FieldSpan(3)), dcmRef, dcpRef, dcsRef, dcqRef, dwlRef,
            dclRef, dplRef, authorityHead, drs.Revision, drs.EntryCount, drs.CurrentHead.Span,
            dcm.FieldSpan(9), leaseExpires, input.KeyId(0).Span, input.KeyId(1).Span, input.KeyId(2).Span,
            input.KeyId(3).Span, input.KeyId(4).Span, input.KeyId(5).Span, input.KeyId(6).Span,
            dcm.CanonicalSpan, dcp.CanonicalSpan, drs.Record.CanonicalSpan, dpl.CanonicalSpan);
    }

    internal static void VerifyComponentRows(
        OwnedRecord dcs, OwnedRecord dcm, ReadOnlySpan<byte> dcmRef,
        OwnedRecord dcp, ReadOnlySpan<byte> dcpRef, ComponentKind componentKind)
    {
        Equal(dcs.FieldSpan(1), dcm.FieldSpan(1), "DCS network mismatch.");
        Equal(dcs.FieldSpan(3), dcm.FieldSpan(2), "DCS reset mismatch.");
        Equal(dcs.FieldSpan(6), dcmRef, "DCS DCM mismatch.");
        var rows = dcs.FieldSpan(11);
        var priorKind = 0;
        var found = false;
        for (var offset = 0; offset < rows.Length; offset += 104)
        {
            var kind = BinaryPrimitives.ReadUInt16BigEndian(rows.Slice(offset,2));
            if (kind <= priorKind || !Enum.IsDefined(typeof(ComponentKind), (ushort)kind))
                Invalid("DCS component rows are not strictly sorted and closed.");
            priorKind = kind;
            if (kind != (ushort)componentKind) continue;
            Equal(rows.Slice(offset + 2,32), dcp.FieldSpan(2), "DCS component subject mismatch.");
            Equal(rows.Slice(offset + 34,38), dcpRef, "DCS DCP mismatch.");
            Equal(rows.Slice(offset + 72,32), dcp.FieldSpan(17), "DCS schema fingerprint mismatch.");
            found = true;
        }
        if (!found) Invalid("DCS omits the expected component row.");
    }

    private static async ValueTask VerifyHmacAsync(
        OwnedRecord record, ReadOnlyMemory<byte> keyId,
        IProtectedHmacProvider provider, CancellationToken cancellationToken)
    {
        var finalTag = record.Definition.Fields.Count;
        var definition = record.Definition with
        {
            Fields = record.Definition.Fields.Take(finalTag - 1).ToArray(),
            MinimumLength = 12,
            OmittedSigningFieldIndexes = new HashSet<int>()
        };
        var fields = Enumerable.Range(1, finalTag - 1)
            .Select(tag => (ReadOnlyMemory<byte>)record.FieldCopy(tag)).ToArray();
        var unsigned = CanonicalGrammar.Encode(definition, fields);
        var request = new ProtectedHmacRequest(
            ArtifactRegistry.GetProtectedDomain(record.Definition.Magic),
            ArtifactRegistry.ProtectedHmacSha256, keyId.Span, unsigned);
        var returned = await provider.ComputeTagAsync(request, cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var tag = returned.ToArray();
        if (tag.Length != 32 || !CanonicalGrammar.FixedEquals(tag, record.FieldSpan(finalTag)))
            throw new RecordException(RecordError.InvalidSignature,
                "The current cutover protected HMAC is invalid.");
    }

    private static OwnedRecord Decode(
        CurrentCutoverRestoreInput input, int index, RecordDefinition definition) =>
        CanonicalGrammar.DecodeOwned(input.Record(index).Span, definition);
    private static byte[] Ref(ArtifactType type, OwnedRecord record) =>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type, record.CanonicalSpan));
    private static void VerifySignature(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> signing, ReadOnlySpan<byte> key)
    {
        try
        {
            if (!PublicKeyAuth.VerifyDetached(signature.ToArray(), signing.ToArray(), key.ToArray()))
                throw new CryptographicException();
        }
        catch (CryptographicException)
        {
            throw new RecordException(RecordError.InvalidSignature,
                "A current cutover signature is invalid.");
        }
    }
    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string message)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected)) Invalid(message);
    }
    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
