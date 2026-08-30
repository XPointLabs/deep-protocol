using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

internal sealed class IdentityAuthorityVerifier
{
    private const string RevocationSnapshotDomain = "Deep/IdentityAuth/V1/revocation-snapshot";
    private const string RevocationHeadDomain = "Deep/IdentityAuth/V1/revocation-entry-head";
    private const string KeyRotationDomain = "Deep/IdentityAuth/V1/key-rotation";
    private const string KeyRevocationDomain = "Deep/IdentityAuth/V1/key-revocation";
    private const string KeyHashDomain = "Deep/IdentityAuth/V1/key-hash";
    private const string DeviceDomain = "Deep/IdentityAuth/V1/device-certificate";
    private const string MailboxDomain = "Deep/IdentityAuth/V1/mailbox-role-certificate";
    private const string MailboxOwnerIdDomain = "Deep/IdentityAuth/V1/mailbox-owner-id";
    private readonly object _nonceGate = new();
    private readonly HashSet<string> _usedDxpNonces = new(StringComparer.Ordinal);

    internal VerifiedIdentityAuthority CreateGenesisAuthority(
        ReadOnlySpan<byte> accountCertificateCanonical,
        ReadOnlySpan<byte> revocationSnapshotCanonical,
        IReadOnlyList<RevocationCatalogSource> catalogSources,
        ulong verificationTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(catalogSources);
        var account = IdentityVerifier.VerifyAccountCertificate(accountCertificateCanonical);
        if (account.Certificate.CertificateGeneration != 1)
            Invalid("A genesis authority requires DPA1 certificate generation one.");
        var keys = new[]
        {
            GenesisKey(account, KeyScope.DeviceCertificateIssuer,
                account.Certificate.DeviceIssuerEd25519PublicKey.Span),
            GenesisKey(account, KeyScope.AccountRevocation,
                account.Certificate.RevocationEd25519PublicKey.Span),
            GenesisKey(account, KeyScope.ResetControl,
                account.Certificate.ResetControlEd25519PublicKey.Span)
        };
        var revocationKey = keys[1];
        var revocations = VerifySnapshot(
            revocationSnapshotCanonical,
            account,
            revocationKey,
            catalogSources,
            verificationTimeUnixSeconds);
        if (revocations.Snapshot.Revision != 1)
            Invalid("A genesis DRS1 revision must be one.");
        return new VerifiedIdentityAuthority(account, revocations, keys);
    }

    internal VerifiedIdentityAuthority RestoreCurrentAuthority(
        ReadOnlySpan<byte> accountCertificateCanonical,
        ReadOnlySpan<byte> currentRevocationSnapshotCanonical,
        IReadOnlyList<ReadOnlyMemory<byte>> orderedKeyTransitions,
        IReadOnlyList<RevocationCatalogSource> catalogSources,
        ulong verificationTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(orderedKeyTransitions);
        ArgumentNullException.ThrowIfNull(catalogSources);
        var account = IdentityVerifier.VerifyAccountCertificate(accountCertificateCanonical);
        if (account.Certificate.CertificateGeneration != 1)
            Invalid("A recovered identity requires the immutable generation-one DPA1 anchor.");
        var decodedSnapshot = IdentityCodec.DecodeRevocationSnapshot(
            currentRevocationSnapshotCanonical);
        var provisional = new VerifiedRevocationState(
            account, decodedSnapshot, new RevocationCatalog([]));
        var authority = new VerifiedIdentityAuthority(account, provisional,
        [
            GenesisKey(account, KeyScope.DeviceCertificateIssuer,
                account.Certificate.DeviceIssuerEd25519PublicKey.Span),
            GenesisKey(account, KeyScope.AccountRevocation,
                account.Certificate.RevocationEd25519PublicKey.Span),
            GenesisKey(account, KeyScope.ResetControl,
                account.Certificate.ResetControlEd25519PublicKey.Span)
        ]);
        foreach (var canonical in orderedKeyTransitions)
        {
            if (canonical.Length == 412)
            {
                var rotation = IdentityCodec.DecodeKeyRotation(canonical.Span);
                if (rotation.Scope == KeyScope.ReleaseRoot) continue;
                ApplyKeyRotation(authority, canonical.Span, verificationTimeUnixSeconds);
            }
            else if (canonical.Length == 300)
            {
                var revocation = IdentityCodec.DecodeKeyRevocation(canonical.Span);
                if (revocation.Scope == KeyScope.ReleaseRoot) continue;
                ApplyKeyRevocation(authority, canonical.Span, verificationTimeUnixSeconds);
            }
            else
                Invalid("A recovered identity key transition has an invalid length.");
        }
        var currentRevocationKey = authority.GetKeyAuthority(KeyScope.AccountRevocation);
        if (currentRevocationKey.IsTerminal)
            throw new RecordException(RecordError.Revoked,
                "The recovered account-revocation key is terminal.");
        authority.Revocations = VerifySnapshot(
            currentRevocationSnapshotCanonical,
            account,
            currentRevocationKey,
            catalogSources,
            verificationTimeUnixSeconds);
        return authority;
    }

    internal VerifiedKeyAuthority ApplyKeyRotation(
        VerifiedIdentityAuthority authority,
        ReadOnlySpan<byte> canonical,
        ulong verificationTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var rotation = IdentityCodec.DecodeKeyRotation(canonical);
        lock (authority.Gate)
        {
            authority.EnsureUsable();
            var record = rotation.Record;
            var scope = ParseAccountScope(record.FieldSpan(2)[0]);
            if (record.FieldSpan(10)[0] != (byte)KeyAction.Rotate)
                Invalid("KRT1 requires the Rotate action.");
            var current = authority.GetKeyAuthority(scope);
            var generation = Scalars.UInt64(record.FieldSpan(5));
            if (generation == current.Generation &&
                CanonicalGrammar.FixedEquals(rotation.CanonicalHash.Span, current.TransitionCanonicalHash))
                return current;
            BindKeyCandidate(record, authority, current, rotation.PredecessorReference, generation);
            Nonzero(record.FieldSpan(8), "KRT1 new public key");
            if (CanonicalGrammar.FixedEquals(record.FieldSpan(8), current.CurrentEd25519PublicKey.Span))
                Invalid("KRT1 must change the current public key.");
            EnsureKeySeparation(authority, scope, record.FieldSpan(8));
            Effective(record.FieldSpan(9), verificationTimeUnixSeconds);
            var signing = CanonicalGrammar.GetSigningBytes(record, KeyRotationDomain);
            VerifySignature(record.FieldSpan(11), signing, current.CurrentEd25519PublicKey.Span);
            VerifySignature(record.FieldSpan(12), signing, record.FieldSpan(8));
            var next = new VerifiedKeyAuthority(
                scope,
                generation,
                record.FieldSpan(8),
                CanonicalGrammar.ComputeReference(ArtifactType.Krt1, record.CanonicalSpan),
                rotation.CanonicalHash.Span,
                terminal: false);
            authority.SetKey(next);
            authority.RecordTransition(ArtifactType.Krt1, next, record.CanonicalSpan);
            return next;
        }
    }

    internal VerifiedKeyAuthority ApplyKeyRevocation(
        VerifiedIdentityAuthority authority,
        ReadOnlySpan<byte> canonical,
        ulong verificationTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var revocation = IdentityCodec.DecodeKeyRevocation(canonical);
        lock (authority.Gate)
        {
            authority.EnsureUsable();
            var record = revocation.Record;
            var scope = ParseAccountScope(record.FieldSpan(2)[0]);
            if (record.FieldSpan(9)[0] != (byte)KeyAction.Revoke)
                Invalid("KRF1 requires the Revoke action.");
            var current = authority.GetKeyAuthority(scope);
            if (current.IsTerminal)
                throw new RecordException(RecordError.Revoked, "The key role is terminally revoked.");
            var generation = Scalars.UInt64(record.FieldSpan(5));
            if (generation == current.Generation &&
                CanonicalGrammar.FixedEquals(revocation.CanonicalHash.Span, current.TransitionCanonicalHash))
                return current;
            BindKeyCandidate(record, authority, current, revocation.PredecessorReference, generation);
            Effective(record.FieldSpan(8), verificationTimeUnixSeconds);
            var signing = CanonicalGrammar.GetSigningBytes(record, KeyRevocationDomain);
            VerifySignature(record.FieldSpan(10), signing, current.CurrentEd25519PublicKey.Span);
            var next = new VerifiedKeyAuthority(
                scope,
                generation,
                current.CurrentEd25519PublicKey.Span,
                CanonicalGrammar.ComputeReference(ArtifactType.Krf1, record.CanonicalSpan),
                revocation.CanonicalHash.Span,
                terminal: true);
            authority.SetKey(next);
            authority.RecordTransition(ArtifactType.Krf1, next, record.CanonicalSpan);
            return next;
        }
    }

    internal VerifiedRevocationState ApplyRevocationSnapshot(
        VerifiedIdentityAuthority authority,
        ReadOnlySpan<byte> canonical,
        IReadOnlyList<RevocationCatalogSource> catalogSources,
        ulong verificationTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(catalogSources);
        var frozen = canonical.ToArray();
        lock (authority.Gate)
        {
            authority.EnsureUsable();
            var currentKey = authority.GetKeyAuthority(KeyScope.AccountRevocation);
            if (currentKey.IsTerminal)
                throw new RecordException(RecordError.Revoked, "The revocation key is terminally revoked.");
            var candidate = VerifySnapshot(
                frozen,
                authority.Account,
                currentKey,
                catalogSources,
                verificationTimeUnixSeconds);
            var prior = authority.Revocations;
            if (candidate.Snapshot.Revision == prior.Snapshot.Revision)
            {
                if (CanonicalGrammar.FixedEquals(
                        candidate.Snapshot.CanonicalHash.Span,
                        prior.Snapshot.CanonicalHash.Span))
                    return prior;
                authority.LatchFork();
                throw new RecordException(RecordError.ForkDetected, "A changed same-revision DRS1 forked.");
            }
            if (prior.Catalog.IsAccountTerminal)
                throw new RecordException(RecordError.Revoked, "A terminal DRS1 has no successor.");
            if (candidate.Snapshot.Revision != checked(prior.Snapshot.Revision + 1))
                Transition("DRS1 revisions must advance exactly by one.");

            var oldRecord = prior.Snapshot.Record;
            var newRecord = candidate.Snapshot.Record;
            var sameTransition = newRecord.FieldSpan(6).SequenceEqual(oldRecord.FieldSpan(6)) &&
                                 newRecord.FieldSpan(7).SequenceEqual(oldRecord.FieldSpan(7));
            var oldEntries = oldRecord.FieldSpan(10);
            var newEntries = newRecord.FieldSpan(10);
            var append = sameTransition &&
                         candidate.Snapshot.EntryCount == prior.Snapshot.EntryCount + 1 &&
                         newEntries[..oldEntries.Length].SequenceEqual(oldEntries);
            var resign = !sameTransition &&
                         candidate.Snapshot.EntryCount == prior.Snapshot.EntryCount &&
                         newEntries.SequenceEqual(oldEntries) &&
                         currentKey.Generation == checked(Scalars.UInt64(oldRecord.FieldSpan(6)) + 1);
            if (append == resign)
                Transition("A DRS1 successor must append one entry or perform one exact key-only re-sign.");
            authority.Revocations = candidate;
            return candidate;
        }
    }

    internal VerifiedDevice VerifyDeviceCertificate(
        VerifiedIdentityAuthority authority,
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> dxpTranscript,
        ReadOnlySpan<byte> dxpProof,
        ReadOnlySpan<byte> issuerEphemeralPrivateKey,
        ulong verificationTimeUnixSeconds,
        VerifiedDevice? predecessor = null)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var certificate = IdentityCodec.DecodeDeviceCertificate(canonical);
        var transcript = dxpTranscript.ToArray();
        var proof = dxpProof.ToArray();
        lock (authority.Gate)
        {
            authority.EnsureUsable();
            var issuer = authority.GetKeyAuthority(KeyScope.DeviceCertificateIssuer);
            if (issuer.IsTerminal)
                throw new RecordException(RecordError.Revoked, "The device issuer key is revoked.");
            var record = certificate.Record;
            BindIdentity(record, authority, 1, 2, 3);
            Nonzero(record.FieldSpan(4), "device ID");
            Nonzero(record.FieldSpan(6), "device Ed25519 key");
            Nonzero(record.FieldSpan(7), "device X25519 key");
            Nonzero(record.FieldSpan(8), "device revocation handle");
            if (CanonicalGrammar.FixedEquals(record.FieldSpan(6), record.FieldSpan(7)))
                Invalid("Device Ed25519 and X25519 keys must be independent.");
            if (Scalars.UInt16(record.FieldSpan(19)) != ArtifactRegistry.IdentityAuthV1Ed25519)
                Invalid("DPD1 suite must be exactly IdentityAuthV1Ed25519.");
            if (Scalars.UInt64(record.FieldSpan(18)) != (ulong)DeviceCapabilities.MailboxRoleIssuer)
                Invalid("DPD1 capabilities must be exactly MailboxRoleIssuer in Wave 1.");
            BindPredecessor(certificate, predecessor);
            BindCurrentKey(record, issuer, 9, 10, 11);
            BindObservedDrs(record, authority.Revocations, 12, 13, 14, 15);
            Window(record.FieldSpan(16), record.FieldSpan(17), verificationTimeUnixSeconds);
            var signing = CanonicalGrammar.GetSigningBytes(record, DeviceDomain);
            var unsignedHash = DxpSubjectProjection.HashDevice(record);
            var nonceKey = Convert.ToHexString(X25519PossessionVerifier.GetNonceLedgerKey(transcript));
            lock (_nonceGate)
                if (_usedDxpNonces.Contains(nonceKey)) Invalid("The DXP1 nonce was already consumed.");
            var possession = X25519PossessionVerifier.Verify(
                transcript,
                proof,
                issuerEphemeralPrivateKey,
                X25519PossessionRole.Device,
                record.FieldSpan(1),
                unsignedHash,
                record.FieldSpan(7),
                verificationTimeUnixSeconds);
            Equal(record.FieldSpan(21), possession.TranscriptHash.Span, "DPD1 X25519 transcript hash");
            VerifySignature(record.FieldSpan(22), signing, record.FieldSpan(6));
            VerifySignature(record.FieldSpan(23), signing, issuer.CurrentEd25519PublicKey.Span);
            if (authority.Revocations.Catalog.Contains(ArtifactType.Dpd1, certificate.CanonicalHash.Span))
                throw new RecordException(RecordError.Revoked, "The device certificate is revoked.");
            lock (_nonceGate)
                if (!_usedDxpNonces.Add(nonceKey)) Invalid("The DXP1 nonce was concurrently consumed.");
            return new VerifiedDevice(certificate, authority.Revocations, possession);
        }
    }

    internal VerifiedDevice RestoreDeviceCertificate(
        VerifiedIdentityAuthority authority,
        ReadOnlySpan<byte> canonical,
        DxpReceiptRelative possessionReceipt,
        ulong verificationTimeUnixSeconds,
        VerifiedDevice? predecessor = null)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(possessionReceipt);
        var certificate = IdentityCodec.DecodeDeviceCertificate(canonical);
        lock (authority.Gate)
        {
            authority.EnsureUsable();
            var issuer = authority.GetKeyAuthority(KeyScope.DeviceCertificateIssuer);
            if (issuer.IsTerminal)
                throw new RecordException(RecordError.Revoked, "The device issuer key is revoked.");
            var record = certificate.Record;
            BindIdentity(record, authority, 1, 2, 3);
            Nonzero(record.FieldSpan(4), "device ID");
            Nonzero(record.FieldSpan(6), "device Ed25519 key");
            Nonzero(record.FieldSpan(7), "device X25519 key");
            Nonzero(record.FieldSpan(8), "device revocation handle");
            if (CanonicalGrammar.FixedEquals(record.FieldSpan(6), record.FieldSpan(7)))
                Invalid("Device Ed25519 and X25519 keys must be independent.");
            if (Scalars.UInt16(record.FieldSpan(19)) != ArtifactRegistry.IdentityAuthV1Ed25519 ||
                Scalars.UInt64(record.FieldSpan(18)) != (ulong)DeviceCapabilities.MailboxRoleIssuer)
                Invalid("DPD1 suite or capability mask is invalid.");
            BindPredecessor(certificate, predecessor);
            BindCurrentKey(record, issuer, 9, 10, 11);
            BindObservedDrs(record, authority.Revocations, 12, 13, 14, 15);
            Window(record.FieldSpan(16), record.FieldSpan(17), verificationTimeUnixSeconds);
            if (possessionReceipt.Phase != DxpReceiptPhase.Verified ||
                possessionReceipt.Role != X25519PossessionRole.Device)
                Invalid("DPD1 restore requires a Verified Device DXR1.");
            Equal(possessionReceipt.Record.FieldSpan(3), record.FieldSpan(1), "DPD1/DXR1 network");
            Equal(possessionReceipt.Record.FieldSpan(5), DxpSubjectProjection.HashDevice(record),
                "DPD1/DXR1 subject projection");
            Equal(possessionReceipt.Record.FieldSpan(6), record.FieldSpan(7), "DPD1/DXR1 holder key");
            Equal(possessionReceipt.Record.FieldSpan(13), record.FieldSpan(21), "DPD1/DXR1 transcript");
            var reference = CanonicalGrammar.EncodeReference(
                CanonicalGrammar.ComputeReference(ArtifactType.Dpd1, record.CanonicalSpan));
            Equal(possessionReceipt.Record.FieldSpan(14), reference, "DPD1/DXR1 subject reference");
            var signing = CanonicalGrammar.GetSigningBytes(record, DeviceDomain);
            VerifySignature(record.FieldSpan(22), signing, record.FieldSpan(6));
            VerifySignature(record.FieldSpan(23), signing, issuer.CurrentEd25519PublicKey.Span);
            if (authority.Revocations.Catalog.Contains(ArtifactType.Dpd1, certificate.CanonicalHash.Span))
                throw new RecordException(RecordError.Revoked, "The device certificate is revoked.");
            return new VerifiedDevice(
                certificate,
                authority.Revocations,
                new X25519Possession(X25519PossessionRole.Device, record.FieldSpan(21)));
        }
    }

    internal VerifiedDevice RestoreDeviceCertificateFromRecovery(
        VerifiedIdentityAuthority authority,
        ReadOnlySpan<byte> canonical,
        ulong verificationTimeUnixSeconds,
        VerifiedDevice? predecessor = null)
    {
        ArgumentNullException.ThrowIfNull(authority);
        var certificate = IdentityCodec.DecodeDeviceCertificate(canonical);
        lock (authority.Gate)
        {
            authority.EnsureUsable();
            var issuer = authority.GetKeyAuthority(KeyScope.DeviceCertificateIssuer);
            if (issuer.IsTerminal)
                throw new RecordException(RecordError.Revoked, "The device issuer key is revoked.");
            var record = certificate.Record;
            BindIdentity(record, authority, 1, 2, 3);
            Nonzero(record.FieldSpan(4), "device ID");
            Nonzero(record.FieldSpan(6), "device Ed25519 key");
            Nonzero(record.FieldSpan(7), "device X25519 key");
            Nonzero(record.FieldSpan(8), "device revocation handle");
            Nonzero(record.FieldSpan(21), "device X25519 transcript hash");
            if (CanonicalGrammar.FixedEquals(record.FieldSpan(6), record.FieldSpan(7)) ||
                Scalars.UInt16(record.FieldSpan(19)) != ArtifactRegistry.IdentityAuthV1Ed25519 ||
                Scalars.UInt64(record.FieldSpan(18)) != (ulong)DeviceCapabilities.MailboxRoleIssuer)
                Invalid("DPD1 recovery suite, capability, or key separation is invalid.");
            BindPredecessor(certificate, predecessor);
            BindCurrentKey(record, issuer, 9, 10, 11);
            BindObservedDrs(record, authority.Revocations, 12, 13, 14, 15);
            Window(record.FieldSpan(16), record.FieldSpan(17), verificationTimeUnixSeconds);
            var signing = CanonicalGrammar.GetSigningBytes(record, DeviceDomain);
            VerifySignature(record.FieldSpan(22), signing, record.FieldSpan(6));
            VerifySignature(record.FieldSpan(23), signing, issuer.CurrentEd25519PublicKey.Span);
            if (authority.Revocations.Catalog.Contains(ArtifactType.Dpd1, certificate.CanonicalHash.Span))
                throw new RecordException(RecordError.Revoked, "The device certificate is revoked.");
            return new VerifiedDevice(certificate, authority.Revocations,
                new X25519Possession(X25519PossessionRole.Device, record.FieldSpan(21)));
        }
    }

    internal VerifiedMailboxRole VerifyMailboxRoleCertificate(
        VerifiedIdentityAuthority authority,
        ReadOnlySpan<byte> canonical,
        VerifiedDevice device,
        ulong verificationTimeUnixSeconds,
        VerifiedMailboxRole? predecessor = null)
    {
        ArgumentNullException.ThrowIfNull(authority);
        ArgumentNullException.ThrowIfNull(device);
        var certificate = IdentityCodec.DecodeMailboxRoleCertificate(canonical);
        lock (authority.Gate)
        {
            authority.EnsureUsable();
            if (device.Certificate.Capabilities != DeviceCapabilities.MailboxRoleIssuer)
                Invalid("The device is not a mailbox-role issuer.");
            if (!ReferenceEquals(device.Revocations, authority.Revocations))
                Invalid("The device capability is not sealed to the exact current DRS1.");
            var record = certificate.Record;
            BindIdentity(record, authority, 1, 2, 3);
            Equal(record.FieldSpan(4), device.Certificate.DeviceId.Span, "DPM1 device ID");
            Reference(
                CanonicalGrammar.DecodeReference(record.FieldSpan(5)),
                ArtifactType.Dpd1,
                device.Certificate.CanonicalBytes.Span,
                device.Certificate.CanonicalHash.Span);
            Nonzero(record.FieldSpan(6), "mailbox owner ID");
            Nonzero(record.FieldSpan(8), "mailbox Ed25519 key");
            Nonzero(record.FieldSpan(9), "mailbox revocation handle");
            Span<byte> ownerPreimage = stackalloc byte[16 + 32 + 32];
            record.FieldSpan(1).CopyTo(ownerPreimage);
            record.FieldSpan(2).CopyTo(ownerPreimage[16..]);
            record.FieldSpan(8).CopyTo(ownerPreimage[48..]);
            Equal(record.FieldSpan(6), CanonicalGrammar.Sha256Domain(
                MailboxOwnerIdDomain,
                ownerPreimage), "mailbox owner ID");
            if (CanonicalGrammar.FixedEquals(record.FieldSpan(8), device.Certificate.DeviceEd25519PublicKey.Span))
                Invalid("The mailbox and device signing keys must be distinct.");
            var capabilities = Scalars.UInt64(record.FieldSpan(16));
            if (capabilities == 0 || (capabilities & ~(ulong)(
                    MailboxCapabilities.RouteOwnerControl |
                    MailboxCapabilities.RouterCertificateIssuer)) != 0)
                Invalid("DPM1 has zero or unknown capability bits.");
            BindMailboxPredecessor(certificate, predecessor);
            BindObservedDrs(record, authority.Revocations, 10, 11, 12, 13);
            Window(record.FieldSpan(14), record.FieldSpan(15), verificationTimeUnixSeconds);
            var signing = CanonicalGrammar.GetSigningBytes(record, MailboxDomain);
            VerifySignature(record.FieldSpan(18), signing, device.Certificate.DeviceEd25519PublicKey.Span);
            VerifySignature(record.FieldSpan(19), signing, record.FieldSpan(8));
            if (authority.Revocations.Catalog.Contains(ArtifactType.Dpd1, device.Certificate.CanonicalHash.Span) ||
                authority.Revocations.Catalog.Contains(ArtifactType.Dpm1, certificate.CanonicalHash.Span))
                throw new RecordException(RecordError.Revoked, "The device or mailbox role is revoked.");
            return new VerifiedMailboxRole(certificate, device);
        }
    }

    private static VerifiedRevocationState VerifySnapshot(
        ReadOnlySpan<byte> canonical,
        VerifiedAccount account,
        VerifiedKeyAuthority revocationKey,
        IReadOnlyList<RevocationCatalogSource> catalogSources,
        ulong verificationTimeUnixSeconds)
    {
        var snapshot = IdentityCodec.DecodeRevocationSnapshot(canonical);
        var record = snapshot.Record;
        Equal(record.FieldSpan(1), account.Certificate.NetworkId.Span, "DRS1 network");
        Equal(record.FieldSpan(2), account.DeepAccountIdHash.Span, "DRS1 account hash");
        if (Scalars.UInt64(record.FieldSpan(3)) != account.Certificate.AccountGeneration ||
            Scalars.UInt64(record.FieldSpan(4)) == 0)
            Invalid("The DRS1 account generation or revision is invalid.");
        var issuedAt = Scalars.UInt64(record.FieldSpan(5));
        if (issuedAt == 0 || issuedAt > verificationTimeUnixSeconds)
            throw new RecordException(RecordError.Expired, "DRS1 is issued in the future or at zero.");
        BindCurrentKey(record, revocationKey, 6, 7, 8);
        var catalog = VerifyCatalog(record, account, catalogSources);
        VerifySignature(
            record.FieldSpan(12),
            CanonicalGrammar.GetSigningBytes(record, RevocationSnapshotDomain),
            revocationKey.CurrentEd25519PublicKey.Span);
        return new VerifiedRevocationState(account, snapshot, catalog);
    }

    private static RevocationCatalog VerifyCatalog(
        OwnedRecord snapshot,
        VerifiedAccount account,
        IReadOnlyList<RevocationCatalogSource> sources)
    {
        var count = Scalars.UInt16(snapshot.FieldSpan(9));
        if (sources.Count != count) Invalid("The DRT1 catalog count does not match DRS1.");
        var entries = snapshot.FieldSpan(10);
        var verified = new List<RevocationCatalogEntry>(count);
        var seenTargets = new HashSet<string>(StringComparer.Ordinal);
        var previousHead = new byte[32];
        var accountTuple = new byte[56];
        var payload = new byte[158];
        snapshot.FieldSpan(1).CopyTo(accountTuple);
        snapshot.FieldSpan(2).CopyTo(accountTuple.AsSpan(16));
        snapshot.FieldSpan(3).CopyTo(accountTuple.AsSpan(48));
        for (var index = 0; index < count; index++)
        {
            var row = entries.Slice(index * 62, 62);
            var kind = ParseTargetKind(row[0]);
            if (row[57..62].IndexOfAnyExcept((byte)0) >= 0) Invalid("A DRS1 reserved field is nonzero.");
            var revokedAt = Scalars.UInt64(row.Slice(47, 8));
            if (revokedAt == 0 || revokedAt > Scalars.UInt64(snapshot.FieldSpan(5)))
                Invalid("A DRS1 revoked-at time is invalid.");
            var reason = ParseReason(BinaryPrimitives.ReadUInt16BigEndian(row.Slice(55, 2)));
            if (kind == RevocationTargetKind.AccountTerminal !=
                (reason == RevocationReason.AccountShutdown))
                Invalid("AccountShutdown is reserved exactly for AccountTerminal.");
            if (kind == RevocationTargetKind.AccountTerminal && index != count - 1)
                Invalid("AccountTerminal must be the final DRS1 entry.");
            if (count == 1024 && index == 1023 && kind != RevocationTargetKind.AccountTerminal)
                Invalid("The final DRS1 capacity slot is reserved for AccountTerminal.");

            var target = IdentityCodec.DecodeRevocationTarget(sources[index].TargetSpan);
            Equal(target.AccountHash.Span, account.DeepAccountIdHash.Span, "DRT1 account hash");
            if (target.TargetKind != kind || target.TargetGeneration != Scalars.UInt64(row.Slice(39, 8)))
                Invalid("The DRT1 kind or generation does not match its DRS1 row.");
            var targetReference = CanonicalGrammar.ComputeReference(
                ArtifactType.Drt1,
                target.Record.CanonicalSpan);
            Reference(
                CanonicalGrammar.DecodeReference(row.Slice(1, 38)),
                ArtifactType.Drt1,
                target.CanonicalBytes.Span,
                targetReference.CanonicalHash.Span);
            VerifyTargetCertificate(target, sources[index].CertificateSpan, account);
            if (!seenTargets.Add(Convert.ToHexString(target.CertificateReference.CanonicalHash.Span)))
                Invalid("The DRS1 catalog repeats a target certificate.");
            verified.Add(new RevocationCatalogEntry(target, revokedAt, reason,
                sources[index].CertificateSpan, sources[index].PredecessorDrsSpan));

            payload.AsSpan().Clear();
            accountTuple.CopyTo(payload);
            BinaryPrimitives.WriteUInt64BigEndian(payload.AsSpan(56, 8), checked((ulong)index));
            previousHead.CopyTo(payload.AsSpan(64, 32));
            row.CopyTo(payload.AsSpan(96));
            previousHead = CanonicalGrammar.Sha256Domain(RevocationHeadDomain, payload);
        }
        Equal(snapshot.FieldSpan(11), previousHead, "DRS1 current head");
        return new RevocationCatalog(verified);
    }

    private static void VerifyTargetCertificate(
        RevocationTarget target,
        ReadOnlySpan<byte> canonical,
        VerifiedAccount account)
    {
        ArtifactType expectedType;
        ReadOnlySpan<byte> handle;
        ulong generation;
        ulong notAfter;
        ReadOnlySpan<byte> artifactCanonical;
        ReadOnlySpan<byte> artifactHash;
        switch (target.TargetKind)
        {
            case RevocationTargetKind.DeviceCertificate:
            {
                var device = IdentityCodec.DecodeDeviceCertificate(canonical);
                Equal(device.AccountHash.Span, account.DeepAccountIdHash.Span, "DRT1 device account");
                expectedType = ArtifactType.Dpd1;
                handle = device.RevocationHandle.Span;
                generation = device.DeviceGeneration;
                notAfter = device.ExpiresAtUnixSeconds;
                artifactCanonical = device.CanonicalBytes.Span;
                artifactHash = device.CanonicalHash.Span;
                break;
            }
            case RevocationTargetKind.MailboxRoleCertificate:
            {
                var mailbox = IdentityCodec.DecodeMailboxRoleCertificate(canonical);
                Equal(mailbox.AccountHash.Span, account.DeepAccountIdHash.Span, "DRT1 mailbox account");
                expectedType = ArtifactType.Dpm1;
                handle = mailbox.RevocationHandle.Span;
                generation = mailbox.RoleGeneration;
                notAfter = mailbox.ExpiresAtUnixSeconds;
                artifactCanonical = mailbox.CanonicalBytes.Span;
                artifactHash = mailbox.CanonicalHash.Span;
                break;
            }
            case RevocationTargetKind.AccountTerminal:
                expectedType = ArtifactType.Dpa1;
                handle = account.Certificate.AccountRevocationHandle.Span;
                generation = account.Certificate.AccountGeneration;
                notAfter = 0;
                artifactCanonical = account.Certificate.CanonicalBytes.Span;
                artifactHash = account.Certificate.CanonicalHash.Span;
                break;
            default:
                Invalid("The DRT1 target kind is unreachable.");
                return;
        }
        Equal(target.RandomRevocationHandle.Span, handle, "DRT1 revocation handle");
        if (target.TargetGeneration != generation || target.TargetNotAfterUnixSeconds != notAfter)
            Invalid("The DRT1 target generation or not-after does not match its certificate.");
        Reference(target.CertificateReference, expectedType, artifactCanonical, artifactHash);
    }

    private static void BindKeyCandidate(
        OwnedRecord record,
        VerifiedIdentityAuthority authority,
        VerifiedKeyAuthority current,
        ArtifactReference predecessor,
        ulong generation)
    {
        Equal(record.FieldSpan(1), authority.Account.Certificate.NetworkId.Span, "key-transition network");
        Equal(record.FieldSpan(3), authority.Account.DeepAccountIdHash.Span, "key-transition account hash");
        if (Scalars.UInt64(record.FieldSpan(4)) != authority.Account.Certificate.AccountGeneration)
            Invalid("The key-transition account generation is invalid.");
        if (generation != checked(current.Generation + 1))
        {
            if (generation <= current.Generation) authority.LatchFork();
            Transition("Key transition generations must advance exactly by one.");
        }
        var expectedPredecessor = current.Generation == 0
            ? CanonicalGrammar.ComputeReference(
                ArtifactType.Dpa1,
                authority.Account.Certificate.CanonicalBytes.Span)
            : current.TransitionReference;
        if (predecessor.Type != expectedPredecessor.Type ||
            predecessor.CanonicalLength != expectedPredecessor.CanonicalLength ||
            !CanonicalGrammar.FixedEquals(
                predecessor.CanonicalHash.Span,
                expectedPredecessor.CanonicalHash.Span))
            Transition("The key-transition predecessor is not the exact current authority artifact.");
        Equal(record.FieldSpan(7), ComputeKeyHash(
            authority.Account.Certificate.NetworkId.Span,
            current.Scope,
            authority.Account.DeepAccountIdHash.Span,
            authority.Account.Certificate.AccountGeneration,
            current.CurrentEd25519PublicKey.Span), "old key hash");
    }

    private static void BindCurrentKey(
        OwnedRecord record,
        VerifiedKeyAuthority authority,
        int generationTag,
        int referenceTag,
        int hashTag)
    {
        if (Scalars.UInt64(record.FieldSpan(generationTag)) != authority.Generation)
            Invalid("The record does not bind the current key generation.");
        var reference = CanonicalGrammar.DecodeReference(record.FieldSpan(referenceTag), allowZero: true);
        if (authority.Generation == 0)
        {
            if (!reference.IsZero) Invalid("A genesis key binding requires a zero transition reference.");
        }
        else if (reference.Type != authority.TransitionReference.Type ||
                 reference.CanonicalLength != authority.TransitionReference.CanonicalLength ||
                 !CanonicalGrammar.FixedEquals(
                     reference.CanonicalHash.Span,
                     authority.TransitionReference.CanonicalHash.Span))
            Invalid("The record does not bind the exact current key transition.");
        Equal(record.FieldSpan(hashTag), ComputeKeyHash(
            record.FieldSpan(1),
            authority.Scope,
            record.FieldSpan(2),
            Scalars.UInt64(record.FieldSpan(3)),
            authority.CurrentEd25519PublicKey.Span), "current key hash");
    }

    private static byte[] ComputeKeyHash(
        ReadOnlySpan<byte> network,
        KeyScope scope,
        ReadOnlySpan<byte> accountHash,
        ulong accountGeneration,
        ReadOnlySpan<byte> publicKey)
    {
        Span<byte> payload = stackalloc byte[16 + 1 + 32 + 8 + 32];
        network.CopyTo(payload);
        payload[16] = (byte)scope;
        accountHash.CopyTo(payload[17..]);
        BinaryPrimitives.WriteUInt64BigEndian(payload[49..57], accountGeneration);
        publicKey.CopyTo(payload[57..]);
        return CanonicalGrammar.Sha256Domain(KeyHashDomain, payload);
    }

    private static VerifiedKeyAuthority GenesisKey(
        VerifiedAccount account,
        KeyScope scope,
        ReadOnlySpan<byte> publicKey) =>
        new(scope, 0, publicKey, default, account.Certificate.CanonicalHash.Span, terminal: false);

    private static void EnsureKeySeparation(
        VerifiedIdentityAuthority authority,
        KeyScope replacing,
        ReadOnlySpan<byte> candidate)
    {
        var accountKeys = new[]
        {
            authority.Account.Certificate.AccountEd25519PublicKey,
            authority.GetKeyAuthority(KeyScope.DeviceCertificateIssuer).CurrentEd25519PublicKey,
            authority.GetKeyAuthority(KeyScope.AccountRevocation).CurrentEd25519PublicKey,
            authority.GetKeyAuthority(KeyScope.ResetControl).CurrentEd25519PublicKey
        };
        for (var index = 0; index < accountKeys.Length; index++)
        {
            if (index == (int)replacing - 1) continue;
            if (CanonicalGrammar.FixedEquals(candidate, accountKeys[index].Span))
                Invalid("A rotated key cannot reuse another account authority role key.");
        }
    }

    private static void BindIdentity(
        OwnedRecord record,
        VerifiedIdentityAuthority authority,
        int networkTag,
        int accountTag,
        int generationTag)
    {
        Equal(record.FieldSpan(networkTag), authority.Account.Certificate.NetworkId.Span, "identity network");
        Equal(record.FieldSpan(accountTag), authority.Account.DeepAccountIdHash.Span, "identity account");
        if (Scalars.UInt64(record.FieldSpan(generationTag)) != authority.Account.Certificate.AccountGeneration)
            Invalid("The identity account generation is invalid.");
    }

    private static void BindObservedDrs(
        OwnedRecord record,
        VerifiedRevocationState revocations,
        int revisionTag,
        int referenceTag,
        int countTag,
        int headTag)
    {
        if (Scalars.UInt64(record.FieldSpan(revisionTag)) != revocations.Snapshot.Revision ||
            Scalars.UInt64(record.FieldSpan(countTag)) != revocations.Snapshot.EntryCount)
            Invalid("The observed DRS1 counters are stale.");
        Reference(
            CanonicalGrammar.DecodeReference(record.FieldSpan(referenceTag)),
            ArtifactType.Drs1,
            revocations.Snapshot.CanonicalBytes.Span,
            revocations.Snapshot.CanonicalHash.Span);
        Equal(record.FieldSpan(headTag), revocations.Snapshot.CurrentHead.Span, "observed DRS1 head");
    }

    private static void BindPredecessor(DeviceCertificate certificate, VerifiedDevice? predecessor)
    {
        var reference = CanonicalGrammar.DecodeReference(certificate.Record.FieldSpan(20), allowZero: true);
        if (certificate.DeviceGeneration == 1)
        {
            if (!reference.IsZero || predecessor is not null)
                Invalid("A generation-one DPD1 requires a zero predecessor.");
            return;
        }
        var prior = predecessor;
        if (prior is null || certificate.DeviceGeneration != checked(prior.Certificate.DeviceGeneration + 1))
            Invalid("A successor DPD1 requires the exact prior generation capability.");
        prior = predecessor!;
        Equal(certificate.DeviceId.Span, prior.Certificate.DeviceId.Span, "DPD1 predecessor device ID");
        Reference(reference, ArtifactType.Dpd1,
            prior.Certificate.CanonicalBytes.Span, prior.Certificate.CanonicalHash.Span);
    }

    private static void BindMailboxPredecessor(
        MailboxRoleCertificate certificate,
        VerifiedMailboxRole? predecessor)
    {
        var reference = CanonicalGrammar.DecodeReference(certificate.Record.FieldSpan(17), allowZero: true);
        if (certificate.RoleGeneration == 1)
        {
            if (!reference.IsZero || predecessor is not null)
                Invalid("A generation-one DPM1 requires a zero predecessor.");
            return;
        }
        var prior = predecessor;
        if (prior is null || certificate.RoleGeneration != checked(prior.Certificate.RoleGeneration + 1))
            Invalid("A successor DPM1 requires the exact prior generation capability.");
        prior = predecessor!;
        Equal(certificate.MailboxOwnerId.Span, prior.Certificate.MailboxOwnerId.Span,
            "DPM1 predecessor owner ID");
        Reference(reference, ArtifactType.Dpm1,
            prior.Certificate.CanonicalBytes.Span, prior.Certificate.CanonicalHash.Span);
    }

    private static KeyScope ParseAccountScope(byte value)
    {
        if (value is not ((byte)KeyScope.DeviceCertificateIssuer or
                          (byte)KeyScope.AccountRevocation or
                          (byte)KeyScope.ResetControl))
            Invalid("Only non-ReleaseRoot account key scopes are accepted here.");
        return (KeyScope)value;
    }

    private static RevocationTargetKind ParseTargetKind(byte value)
    {
        if (value is < 1 or > 3) Invalid("The DRS1 target kind is unknown.");
        return (RevocationTargetKind)value;
    }

    private static RevocationReason ParseReason(ushort value)
    {
        if (value is < 1 or > 4) Invalid("The DRS1 reason is unknown.");
        return (RevocationReason)value;
    }

    private static void Effective(ReadOnlySpan<byte> encoded, ulong now)
    {
        var effectiveAt = Scalars.UInt64(encoded);
        if (effectiveAt == 0 || now < effectiveAt)
            throw new RecordException(RecordError.Expired, "The key transition is not effective.");
    }

    private static void Window(ReadOnlySpan<byte> issuedBytes, ReadOnlySpan<byte> expiresBytes, ulong now)
    {
        var issued = Scalars.UInt64(issuedBytes);
        var expires = Scalars.UInt64(expiresBytes);
        if (issued == 0 || issued >= expires || now < issued || now >= expires)
            throw new RecordException(RecordError.Expired, "The certificate is outside its strict live window.");
    }

    private static void VerifySignature(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != 64 || publicKey.Length != 32 ||
            !PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), publicKey.ToArray()))
            throw new RecordException(RecordError.InvalidSignature, "A DNP1 signature is invalid.");
    }

    private static void Reference(
        ArtifactReference reference,
        ArtifactType type,
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> hash)
    {
        if (reference.Type != type || reference.CanonicalLength != canonical.Length ||
            !CanonicalGrammar.FixedEquals(reference.CanonicalHash.Span, hash))
            Invalid("An artifact reference does not bind the exact canonical artifact.");
    }

    private static void Nonzero(ReadOnlySpan<byte> value, string name)
    {
        if (CanonicalGrammar.IsZero(value)) Invalid($"The {name} is zero.");
    }

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected)) Invalid($"The {name} does not match.");
    }

    private static void Transition(string message) =>
        throw new RecordException(RecordError.InvalidTransition, message);

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}

/// <summary>
/// Verifies exact identity evidence and returns only sealed evidence-relative facts.
/// It accepts no generic crypto callbacks and grants no storage or consumer authority.
/// </summary>
public sealed class IdentityRelativeVerifier
{
    private readonly IdentityAuthorityVerifier _inner = new();
    private readonly object _ownerGate = new();
    private readonly Dictionary<string, byte[]> _ownerPreimages = new(StringComparer.Ordinal);

    public VerifiedIdentityRelative VerifyGenesis(
        ReadOnlySpan<byte> accountCertificateCanonical,
        ReadOnlySpan<byte> revocationSnapshotCanonical,
        IReadOnlyList<RevocationCatalogInput> catalog,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        var sources = catalog.Select(static value => value.Source).ToArray();
        return new VerifiedIdentityRelative(_inner.CreateGenesisAuthority(
            accountCertificateCanonical,
            revocationSnapshotCanonical,
            sources,
            transactionTimeUnixSeconds));
    }

    internal VerifiedIdentityRelative RestoreCurrent(
        ReadOnlySpan<byte> accountCertificateCanonical,
        ReadOnlySpan<byte> currentRevocationSnapshotCanonical,
        IReadOnlyList<ReadOnlyMemory<byte>> orderedKeyTransitions,
        IReadOnlyList<RevocationCatalogSource> catalog,
        ulong transactionTimeUnixSeconds) =>
        new(_inner.RestoreCurrentAuthority(
            accountCertificateCanonical,
            currentRevocationSnapshotCanonical,
            orderedKeyTransitions,
            catalog,
            transactionTimeUnixSeconds));

    public VerifiedIdentityRelative ApplyKeyRotation(
        VerifiedIdentityRelative identity,
        ReadOnlySpan<byte> canonical,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(identity);
        _inner.ApplyKeyRotation(identity.Authority, canonical, transactionTimeUnixSeconds);
        return identity;
    }

    public VerifiedIdentityRelative ApplyKeyRevocation(
        VerifiedIdentityRelative identity,
        ReadOnlySpan<byte> canonical,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(identity);
        _inner.ApplyKeyRevocation(identity.Authority, canonical, transactionTimeUnixSeconds);
        return identity;
    }

    public VerifiedIdentityRelative ApplyRevocationSnapshot(
        VerifiedIdentityRelative identity,
        ReadOnlySpan<byte> canonical,
        IReadOnlyList<RevocationCatalogInput> catalog,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(catalog);
        _inner.ApplyRevocationSnapshot(
            identity.Authority,
            canonical,
            catalog.Select(static value => value.Source).ToArray(),
            transactionTimeUnixSeconds);
        return identity;
    }

    internal VerifiedDeviceRelative VerifyDevice(
        VerifiedIdentityRelative identity,
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> possessionTranscript,
        ReadOnlySpan<byte> possessionProof,
        ReadOnlySpan<byte> issuerEphemeralPrivateKey,
        ulong transactionTimeUnixSeconds,
        VerifiedDeviceRelative? predecessor = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var verified = _inner.VerifyDeviceCertificate(
            identity.Authority,
            canonical,
            possessionTranscript,
            possessionProof,
            issuerEphemeralPrivateKey,
            transactionTimeUnixSeconds,
            predecessor?.Device);
        return new VerifiedDeviceRelative(identity, verified);
    }

    public VerifiedDeviceRelative RestoreDevice(
        VerifiedIdentityRelative identity,
        ReadOnlySpan<byte> canonical,
        DxpReceiptRelative possessionReceipt,
        ulong transactionTimeUnixSeconds,
        VerifiedDeviceRelative? predecessor = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(possessionReceipt);
        var verified = _inner.RestoreDeviceCertificate(
            identity.Authority,
            canonical,
            possessionReceipt,
            transactionTimeUnixSeconds,
            predecessor?.Device);
        return new VerifiedDeviceRelative(identity, verified);
    }

    internal VerifiedDeviceRelative RestoreDeviceFromRecovery(
        VerifiedIdentityRelative identity,
        ReadOnlySpan<byte> canonical,
        ulong transactionTimeUnixSeconds,
        VerifiedDeviceRelative? predecessor = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var verified = _inner.RestoreDeviceCertificateFromRecovery(
            identity.Authority,
            canonical,
            transactionTimeUnixSeconds,
            predecessor?.Device);
        return new VerifiedDeviceRelative(identity, verified);
    }

    public VerifiedMailboxRelative VerifyMailboxRole(
        VerifiedIdentityRelative identity,
        ReadOnlySpan<byte> canonical,
        VerifiedDeviceRelative device,
        ulong transactionTimeUnixSeconds,
        VerifiedMailboxRelative? predecessor = null)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(device);
        if (!ReferenceEquals(device.Identity, identity))
            throw new RecordException(RecordError.InvalidField,
                "The device fact belongs to a different identity verification result.");
        var verified = _inner.VerifyMailboxRoleCertificate(
            identity.Authority,
            canonical,
            device.Device,
            transactionTimeUnixSeconds,
            predecessor?.Mailbox);
        var certificate = verified.Certificate;
        Span<byte> preimage = stackalloc byte[80];
        certificate.NetworkId.Span.CopyTo(preimage);
        certificate.AccountHash.Span.CopyTo(preimage[16..]);
        certificate.MailboxEd25519PublicKey.Span.CopyTo(preimage[48..]);
        var collisionKey = Convert.ToHexString(certificate.NetworkId.Span) + ":" +
                           Convert.ToHexString(certificate.AccountHash.Span) + ":" +
                           Convert.ToHexString(certificate.MailboxOwnerId.Span);
        lock (_ownerGate)
        {
            if (_ownerPreimages.TryGetValue(collisionKey, out var prior) &&
                !CanonicalGrammar.FixedEquals(prior, preimage))
            {
                identity.Authority.LatchFork();
                throw new RecordException(RecordError.ForkDetected,
                    "The mailbox owner ID has conflicting canonical issuance preimages.");
            }
            _ownerPreimages[collisionKey] = preimage.ToArray();
        }
        return new VerifiedMailboxRelative(device, verified);
    }
}

/// <summary>
/// ReleaseRoot and witness verification relative to exact supplied evidence.
/// Every returned value explicitly carries no durable or consumer authority.
/// </summary>
public sealed class ReleaseRootRelativeVerifier
{
    private const string ManifestDomain = "Deep/Cutover/V1/release-root-manifest";
    private const string ManifestKeyIdDomain = "Deep/Cutover/V1/release-manifest-key-id";
    private const string KeyHashDomain = "Deep/IdentityAuth/V1/key-hash";
    private const string RotationDomain = "Deep/IdentityAuth/V1/key-rotation";
    private const string RevocationDomain = "Deep/IdentityAuth/V1/key-revocation";
    private const string DelegationDomain = "Deep/Cutover/V1/witness-delegation";
    private const string SuccessorDomain = "Deep/Cutover/V1/witness-set-successor";
    private const string SetRootDomain = "Deep/Cutover/V1/witness-set-root";
    private const string HeadsDomain = "Deep/Cutover/V1/witness-heads";
    private const string PolicyDomain = "Deep/Cutover/V1/subject-policy";
    private const string TerminalReceiptDomain = "Deep/Cutover/V1/witness-terminal-receipt";
    private const string TerminalQuorumDomain = "Deep/Cutover/V1/witness-terminal-quorum";
    private const string RootChainDomain = "Deep/Cutover/V1/release-root-chain";
    private const string RootAuthorityHeadDomain = "Deep/Cutover/V1/release-root-authority-head";
    private const string HeadLeaseDomain = "Deep/Cutover/V1/head-lease";
    private const string LeaseDigestDomain = "Deep/Cutover/V1/lease-digest";
    private readonly object _restoreGate = new();
    private readonly Dictionary<string, RestoreReplayState> _restoreHeads = new(StringComparer.Ordinal);

    public ReleaseRootRelativeFact VerifyManifest(
        ReleaseRootManifestPin pin,
        ReadOnlySpan<byte> canonical,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(pin);
        var manifest = CutoverCodec.DecodeReleaseRootManifest(canonical);
        var record = manifest.Record;
        Equal(record.FieldSpan(1), pin.NetworkId.Span, "RRM1 pin network");
        if (Scalars.UInt64(record.FieldSpan(2)) != pin.MinimumManifestGeneration ||
            pin.MinimumManifestGeneration != 0 ||
            Scalars.UInt64(record.FieldSpan(4)) != 0)
            Invalid("RRM1 generations must match the zero-generation pin.");
        var reference = CanonicalGrammar.ComputeReference(ArtifactType.Rrm1, record.CanonicalSpan);
        Reference(reference, pin.ExpectedManifestReference, "RRM1 pin reference");
        Equal(record.FieldSpan(9), pin.ManifestSignerKeyId.Span, "RRM1 signer key ID");
        Equal(record.FieldSpan(9), CanonicalGrammar.Sha256Domain(
            ManifestKeyIdDomain,
            pin.ManifestSignerEd25519PublicKey.Span), "RRM1 derived signer key ID");
        if (transactionTimeUnixSeconds < Scalars.UInt64(record.FieldSpan(6)))
            throw new RecordException(RecordError.Expired, "RRM1 is not active at txNow.");
        VerifySignature(
            record.FieldSpan(10),
            CanonicalGrammar.GetSigningBytes(record, ManifestDomain),
            pin.ManifestSignerEd25519PublicKey.Span);
        return new ReleaseRootRelativeFact(
            manifest,
            pin,
            0,
            record.FieldSpan(5),
            reference,
            [],
            [],
            pendingTerminalRevocation: null);
    }

    public ReleaseRootRelativeFact VerifyRotation(
        ReleaseRootRelativeFact current,
        ReadOnlySpan<byte> canonical,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (current.IsTerminalCandidate) Revoked("A terminal ReleaseRoot candidate cannot rotate.");
        var rotation = IdentityCodec.DecodeKeyRotation(canonical);
        var record = rotation.Record;
        BindRootTransition(record, current, rotation.PredecessorReference, KeyAction.Rotate);
        Nonzero(record.FieldSpan(8), "ReleaseRoot rotation public key");
        if (CanonicalGrammar.FixedEquals(record.FieldSpan(8), current.CurrentEd25519PublicKey.Span))
            Invalid("ReleaseRoot rotation must change the key.");
        Effective(record.FieldSpan(9), transactionTimeUnixSeconds);
        var signing = CanonicalGrammar.GetSigningBytes(record, RotationDomain);
        VerifySignature(record.FieldSpan(11), signing, current.CurrentEd25519PublicKey.Span);
        VerifySignature(record.FieldSpan(12), signing, record.FieldSpan(8));
        var reference = CanonicalGrammar.ComputeReference(ArtifactType.Krt1, record.CanonicalSpan);
        return new ReleaseRootRelativeFact(
            current.Manifest,
            current.Pin,
            rotation.TransitionGeneration,
            record.FieldSpan(8),
            reference,
            current.Transitions.Append(reference),
            current.TransitionCanonicals.Append(canonical.ToArray()),
            pendingTerminalRevocation: null);
    }

    public ReleaseRootRelativeFact VerifyRevocation(
        ReleaseRootRelativeFact current,
        ReadOnlySpan<byte> canonical,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(current);
        if (current.IsTerminalCandidate) Revoked("ReleaseRoot already has a terminal candidate.");
        var revocation = IdentityCodec.DecodeKeyRevocation(canonical);
        var record = revocation.Record;
        BindRootTransition(record, current, revocation.PredecessorReference, KeyAction.Revoke);
        Effective(record.FieldSpan(8), transactionTimeUnixSeconds);
        VerifySignature(
            record.FieldSpan(10),
            CanonicalGrammar.GetSigningBytes(record, RevocationDomain),
            current.CurrentEd25519PublicKey.Span);
        var reference = CanonicalGrammar.ComputeReference(ArtifactType.Krf1, record.CanonicalSpan);
        return new ReleaseRootRelativeFact(
            current.Manifest,
            current.Pin,
            current.CurrentGeneration,
            current.CurrentEd25519PublicKey.Span,
            current.CurrentTransitionReference,
            current.Transitions.Append(reference),
            current.TransitionCanonicals.Append(canonical.ToArray()),
            revocation);
    }

    public WitnessDelegationRelativeFact VerifyGenesisWitnessDelegation(
        ReleaseRootRelativeFact root,
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> predecessorFinalHeads288,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(root);
        if (root.CurrentGeneration != 0 || root.IsTerminalCandidate)
            Invalid("Genesis DWD1 requires the nonterminal generation-zero manifest fact.");
        return VerifyDelegationCore(
            root,
            canonical,
            predecessor: null,
            predecessorFinalHeads288,
            transactionTimeUnixSeconds,
            requireActiveAtTransactionTime: true);
    }

    public WitnessDelegationRelativeFact VerifyWitnessSuccessor(
        ReleaseRootRelativeFact root,
        WitnessDelegationRelativeFact predecessor,
        ReadOnlySpan<byte> canonical,
        ReadOnlySpan<byte> predecessorFinalHeads288,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(root);
        ArgumentNullException.ThrowIfNull(predecessor);
        return VerifyDelegationCore(
            root,
            canonical,
            predecessor,
            predecessorFinalHeads288,
            transactionTimeUnixSeconds,
            requireActiveAtTransactionTime: true);
    }

    public WitnessTerminationRelativeFact VerifyWitnessTermination(
        ReleaseRootRelativeFact terminalRoot,
        WitnessDelegationRelativeFact priorDelegation,
        ReadOnlySpan<byte> canonical,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(terminalRoot);
        ArgumentNullException.ThrowIfNull(priorDelegation);
        var krf = terminalRoot.PendingTerminalRevocation ??
            throw new RecordException(RecordError.InvalidTransition,
                "DWT1 requires one exact pending ReleaseRoot KRF1 fact.");
        var termination = CutoverCodec.DecodeWitnessTermination(canonical);
        var record = termination.Record;
        Equal(record.FieldSpan(1), terminalRoot.Manifest.NetworkId.Span, "DWT1 network");
        Reference(CanonicalGrammar.DecodeReference(record.FieldSpan(2)),
            CanonicalGrammar.ComputeReference(ArtifactType.Dwd1,
                priorDelegation.Delegation.CanonicalBytes.Span), "DWT1 prior DWD1");
        if (Scalars.UInt64(record.FieldSpan(3)) != priorDelegation.Delegation.WitnessEpoch ||
            Scalars.UInt64(record.FieldSpan(4)) != terminalRoot.CurrentGeneration)
            Invalid("DWT1 witness epoch or ReleaseRoot generation does not match.");
        Reference(CanonicalGrammar.DecodeReference(record.FieldSpan(5)),
            terminalRoot.CurrentTransitionReference, "DWT1 ReleaseRoot transition");
        Reference(CanonicalGrammar.DecodeReference(record.FieldSpan(6)),
            CanonicalGrammar.ComputeReference(ArtifactType.Krf1, krf.CanonicalBytes.Span),
            "DWT1 KRF1");
        if (Scalars.UInt64(record.FieldSpan(7)) != krf.EffectiveAtUnixSeconds ||
            transactionTimeUnixSeconds < krf.EffectiveAtUnixSeconds)
            throw new RecordException(RecordError.Expired,
                "DWT1 effective time does not match the active KRF1.");
        var rows = record.FieldSpan(9);
        ReadOnlySpan<byte> previousId = default;
        for (var index = 0; index < 3; index++)
        {
            var row = rows.Slice(index * 145, 145);
            if (index != 0 && Compare(previousId, row[..32]) >= 0)
                Invalid("DWT1 witness receipts are not strictly witness-ID sorted.");
            previousId = row[..32];
            WitnessDescriptorRelative? witness = null;
            foreach (var candidate in priorDelegation.Descriptors)
                if (CanonicalGrammar.FixedEquals(candidate.WitnessId.Span, row[..32]))
                {
                    witness = candidate;
                    break;
                }
            if (witness is null)
                throw new RecordException(RecordError.InvalidField,
                    "A DWT1 receipt signer is outside the exact prior DWD1.");
            if (Scalars.UInt64(row.Slice(32, 8)) > priorDelegation.Delegation.MaximumTreeSize ||
                row[72] != (byte)DurabilityClass.FsyncReplicated ||
                Scalars.UInt64(row.Slice(73, 8)) == 0 ||
                Scalars.UInt64(row.Slice(73, 8)) > transactionTimeUnixSeconds)
                Invalid("A DWT1 receipt durability, tree size, or issue time is invalid.");
            var payload = new byte[235];
            var offset = 0;
            for (var tag = 1; tag <= 7; tag++)
            {
                record.FieldSpan(tag).CopyTo(payload.AsSpan(offset));
                offset += record.FieldSpan(tag).Length;
            }
            row[..81].CopyTo(payload.AsSpan(offset));
            VerifySignature(row[81..145], SignatureInput(TerminalReceiptDomain, payload),
                witness.Ed25519PublicKey.Span);
        }
        var quorumPayload = new byte[590];
        var quorumOffset = 0;
        for (var tag = 1; tag <= 7; tag++)
        {
            record.FieldSpan(tag).CopyTo(quorumPayload.AsSpan(quorumOffset));
            quorumOffset += record.FieldSpan(tag).Length;
        }
        record.FieldSpan(8).CopyTo(quorumPayload.AsSpan(quorumOffset));
        quorumOffset += 1;
        rows.CopyTo(quorumPayload.AsSpan(quorumOffset));
        Equal(record.FieldSpan(10), CanonicalGrammar.Sha256Domain(
            TerminalQuorumDomain,
            quorumPayload), "DWT1 quorum digest");
        return new WitnessTerminationRelativeFact(termination, terminalRoot, priorDelegation);
    }

    /// <summary>
    /// Reconstructs the complete bounded ReleaseRoot/DWD ancestry as a relative fact.
    /// The method freezes and decodes every row before performing any signature work.
    /// </summary>
    public ReleaseRootRestoreRelative RestoreAncestryRelative(
        ReleaseRootRestoreInput input,
        ulong transactionTimeUnixSeconds)
    {
        ArgumentNullException.ThrowIfNull(input);
        var manifestBytes = input.ManifestCanonical.ToArray();
        var transitionBytes = input.RootTransitions.Select(static value => value.ToArray()).ToArray();
        var delegationInputs = input.WitnessDelegations.ToArray();
        var delegationBytes = delegationInputs.Select(static value => value.CanonicalDwd.ToArray()).ToArray();
        var predecessorHeads = delegationInputs.Select(static value => value.PredecessorFinalHeads.ToArray()).ToArray();
        var terminalBytes = input.TerminalDwtCanonical.ToArray();
        var leaseBytes = input.FreshDclCanonical.ToArray();

        // Complete bounded preflight. No signature primitive runs above or within this block.
        _ = CutoverCodec.DecodeReleaseRootManifest(manifestBytes);
        for (var index = 0; index < transitionBytes.Length; index++)
        {
            if (transitionBytes[index].Length == 412)
                _ = IdentityCodec.DecodeKeyRotation(transitionBytes[index]);
            else
                _ = IdentityCodec.DecodeKeyRevocation(transitionBytes[index]);
        }
        var decodedDelegations = new WitnessDelegation[delegationBytes.Length];
        var seenDelegations = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < delegationBytes.Length; index++)
        {
            decodedDelegations[index] = CutoverCodec.DecodeWitnessDelegation(delegationBytes[index]);
            var reference = CanonicalGrammar.ComputeReference(ArtifactType.Dwd1, delegationBytes[index]);
            if (!seenDelegations.Add(Convert.ToHexString(reference.CanonicalHash.Span)))
                Transition("ReleaseRoot restore contains a duplicate DWD1 ancestry row.");
            if (decodedDelegations[index].DelegationGeneration != (ulong)index ||
                decodedDelegations[index].WitnessEpoch != checked((ulong)index + 1))
                Transition("ReleaseRoot restore contains a skipped or reordered DWD1 ancestry row.");
            if (index == 0)
            {
                if (!CanonicalGrammar.DecodeReference(
                        decodedDelegations[index].Record.FieldSpan(3), allowZero: true).IsZero)
                    Transition("ReleaseRoot restore genesis DWD1 has a nonzero predecessor.");
            }
            else
            {
                Reference(
                    CanonicalGrammar.DecodeReference(decodedDelegations[index].Record.FieldSpan(3)),
                    CanonicalGrammar.ComputeReference(ArtifactType.Dwd1, delegationBytes[index - 1]),
                    "ReleaseRoot restore DWD1 predecessor");
            }
        }
        if (input.IsTerminal)
            _ = CutoverCodec.DecodeWitnessTermination(terminalBytes);
        else
            PreflightLeaseRows(leaseBytes);

        var root = VerifyManifest(input.Pin, manifestBytes, transactionTimeUnixSeconds);
        var latest = VerifyDelegationCore(
            root,
            delegationBytes[0],
            predecessor: null,
            predecessorHeads[0],
            transactionTimeUnixSeconds,
            requireActiveAtTransactionTime: !input.IsTerminal && delegationBytes.Length == 1);
        var transitionIndex = 0;
        for (var delegationIndex = 1; delegationIndex < delegationBytes.Length; delegationIndex++)
        {
            var desiredRootReference = CanonicalGrammar.DecodeReference(
                decodedDelegations[delegationIndex].Record.FieldSpan(16));
            if (!SameReference(desiredRootReference, root.CurrentTransitionReference))
            {
                if (transitionIndex >= transitionBytes.Length ||
                    transitionBytes[transitionIndex].Length != 412)
                    Transition("A DWD1 changed ReleaseRoot ancestry without one exact paired KRT1.");
                var rotation = IdentityCodec.DecodeKeyRotation(transitionBytes[transitionIndex]);
                root = VerifyRotation(root, transitionBytes[transitionIndex], transactionTimeUnixSeconds);
                transitionIndex++;
                if (decodedDelegations[delegationIndex].ValidFromUnixSeconds <
                    rotation.EffectiveAtUnixSeconds)
                    Transition("A KRT1-paired DWD1 activates before its exact key rotation.");
            }
            latest = VerifyDelegationCore(
                root,
                delegationBytes[delegationIndex],
                latest,
                predecessorHeads[delegationIndex],
                transactionTimeUnixSeconds,
                requireActiveAtTransactionTime:
                    !input.IsTerminal && delegationIndex == delegationBytes.Length - 1);
        }

        WitnessTerminationRelativeFact? termination = null;
        if (input.IsTerminal)
        {
            if (transitionIndex != transitionBytes.Length - 1 ||
                transitionBytes[transitionIndex].Length != 300)
                Transition("Terminal restore requires one final unpaired KRF1 and no transition tail.");
            root = VerifyRevocation(root, transitionBytes[transitionIndex], transactionTimeUnixSeconds);
            transitionIndex++;
            termination = VerifyWitnessTermination(root, latest, terminalBytes, transactionTimeUnixSeconds);
        }
        else if (transitionIndex != transitionBytes.Length)
            Transition("Nonterminal restore contains an unpaired, terminal, or trailing root transition.");

        var tuple = BuildAuthorityTuple(root, latest, termination);
        QuorumLease? lease = null;
        if (!input.IsTerminal)
            lease = VerifyFreshLeaseTail(leaseBytes, root, latest, tuple, transactionTimeUnixSeconds);
        var result = new ReleaseRootRestoreRelative(
            root,
            latest,
            tuple,
            termination,
            lease,
            exactReplay: false,
            delegationBytes,
            predecessorHeads);
        var closureFingerprint = RestoreFingerprint(
            manifestBytes,
            transitionBytes,
            delegationBytes,
            predecessorHeads,
            input.IsTerminal ? terminalBytes : leaseBytes);
        var networkKey = Convert.ToHexString(root.Manifest.NetworkId.Span);
        lock (_restoreGate)
        {
            if (_restoreHeads.TryGetValue(networkKey, out var prior))
            {
                if (CryptographicOperations.FixedTimeEquals(prior.ClosureFingerprint, closureFingerprint))
                    return new ReleaseRootRestoreRelative(
                        root, latest, tuple, termination, lease, exactReplay: true,
                        delegationBytes, predecessorHeads);
                if ((prior.RootGeneration == root.CurrentGeneration &&
                        prior.DwdGeneration == latest.Delegation.DelegationGeneration &&
                        !CryptographicOperations.FixedTimeEquals(
                            prior.AuthorityTuple,
                            tuple.CanonicalTuple.Span)) ||
                    prior.Terminal)
                    throw new RecordException(RecordError.ForkDetected,
                        "Changed same-generation or post-terminal ReleaseRoot restore evidence is a fork.");
                if (root.CurrentGeneration < prior.RootGeneration ||
                    latest.Delegation.DelegationGeneration < prior.DwdGeneration)
                    throw new RecordException(RecordError.InvalidTransition,
                        "ReleaseRoot restore evidence is older than the verifier's observed head.");
            }
            _restoreHeads[networkKey] = new RestoreReplayState(
                closureFingerprint,
                tuple.CanonicalTuple.ToArray(),
                root.CurrentGeneration,
                latest.Delegation.DelegationGeneration,
                input.IsTerminal);
        }
        return result;
    }

    public ReleaseRootLkgHmacTranscript CreateLkgHmacTranscript(
        ReadOnlySpan<byte> canonical)
    {
        var lkg = ProtectedStateCodec.DecodeReleaseRootLastKnownGood(canonical);
        var record = lkg.Record;
        Nonzero(record.FieldSpan(15), "RRL1 protected-state key ID");
        var definition = record.Definition with
        {
            Fields = record.Definition.Fields.Take(15).ToArray(),
            MinimumLength = 12,
            MaximumLength = 502,
            OmittedSigningFieldIndexes = new HashSet<int>()
        };
        var fields = Enumerable.Range(1, 15)
            .Select(tag => (ReadOnlyMemory<byte>)record.FieldCopy(tag)).ToArray();
        var unsigned = CanonicalGrammar.Encode(definition, fields);
        return new ReleaseRootLkgHmacTranscript(
            unsigned,
            record.FieldSpan(15),
            record.FieldSpan(16));
    }

    public async ValueTask<ReleaseRootLkgHmacMatch> VerifyLkgHmacAsync(
        ReadOnlyMemory<byte> canonical,
        IProtectedHmacProvider provider,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(provider);
        cancellationToken.ThrowIfCancellationRequested();
        var frozenCanonical = canonical.ToArray();
        var transcript = CreateLkgHmacTranscript(frozenCanonical);
        var request = new ProtectedHmacRequest(
            transcript.Domain,
            transcript.Suite,
            transcript.ProtectedStateKeyId.Span,
            transcript.UnsignedCanonical.Span);
        var returned = await provider.ComputeTagAsync(request, cancellationToken)
            .ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var ownedTag = returned.ToArray();
        if (ownedTag.Length != 32)
            throw new RecordException(RecordError.InvalidSignature,
                "The protected-state HMAC provider returned a non-32-byte tag.");
        return transcript.MatchComputedTag(ownedTag);
    }

    public ReleaseRootAuthorityTuple CreateAuthorityTuple(
        ReadOnlySpan<byte> canonical,
        ReleaseRootLkgHmacMatch hmacMatch)
    {
        ArgumentNullException.ThrowIfNull(hmacMatch);
        var lkg = ProtectedStateCodec.DecodeReleaseRootLastKnownGood(canonical);
        var expected = CreateLkgHmacTranscript(canonical);
        if (!CanonicalGrammar.FixedEquals(
                expected.UnsignedCanonical.Span,
                hmacMatch.Transcript.UnsignedCanonical.Span) ||
            !CanonicalGrammar.FixedEquals(
                expected.ProtectedStateKeyId.Span,
                hmacMatch.Transcript.ProtectedStateKeyId.Span))
            Invalid("The RRL1 HMAC match belongs to different canonical bytes.");
        var record = lkg.Record;
        var tuple = new byte[282];
        var offset = 0;
        foreach (var tag in new[] { 2,3,4,5,6,7,8,9,10,11,12,13,14 })
        {
            record.FieldSpan(tag).CopyTo(tuple.AsSpan(offset));
            offset += record.FieldSpan(tag).Length;
        }
        if (offset != tuple.Length) throw new InvalidOperationException("RRL1 tuple width drifted.");
        return new ReleaseRootAuthorityTuple(tuple);
    }

    public ReleaseRootTransitionPlan CreateTransitionPlan(
        ReleaseRootAuthorityTuple exactOldTuple,
        ReleaseRootAuthorityTuple exactNewTuple)
    {
        ArgumentNullException.ThrowIfNull(exactOldTuple);
        ArgumentNullException.ThrowIfNull(exactNewTuple);
        if (CanonicalGrammar.FixedEquals(
                exactOldTuple.CanonicalTuple.Span,
                exactNewTuple.CanonicalTuple.Span))
            Invalid("An RRL1 transition plan must change the exact authority tuple.");
        return new ReleaseRootTransitionPlan(exactOldTuple, exactNewTuple);
    }

    private static WitnessDelegationRelativeFact VerifyDelegationCore(
        ReleaseRootRelativeFact root,
        ReadOnlySpan<byte> canonical,
        WitnessDelegationRelativeFact? predecessor,
        ReadOnlySpan<byte> predecessorFinalHeads288,
        ulong transactionTimeUnixSeconds,
        bool requireActiveAtTransactionTime)
    {
        if (root.IsTerminalCandidate) Revoked("A terminal ReleaseRoot candidate cannot authorize DWD1.");
        if (predecessorFinalHeads288.Length != 288)
            Invalid("DWD1 predecessor final heads must be exactly 288 bytes.");
        var delegation = CutoverCodec.DecodeWitnessDelegation(canonical);
        var record = delegation.Record;
        Equal(record.FieldSpan(1), root.Manifest.NetworkId.Span, "DWD1 network");
        var generation = Scalars.UInt64(record.FieldSpan(2));
        var predecessorReference = CanonicalGrammar.DecodeReference(record.FieldSpan(3), allowZero: true);
        var epoch = Scalars.UInt64(record.FieldSpan(4));
        if (predecessor is null)
        {
            if (generation != 0 || epoch != 1 || !predecessorReference.IsZero)
                Invalid("Genesis DWD1 requires generation zero, epoch one, and zero predecessor.");
        }
        else
        {
            if (generation != checked(predecessor.Delegation.DelegationGeneration + 1) ||
                epoch != checked(predecessor.Delegation.WitnessEpoch + 1))
                Transition("DWD1 generation and witness epoch must advance exactly by one.");
            Reference(predecessorReference,
                CanonicalGrammar.ComputeReference(ArtifactType.Dwd1,
                    predecessor.Delegation.CanonicalBytes.Span), "DWD1 predecessor");
            if (delegation.MaximumTreeSize < predecessor.Delegation.MaximumTreeSize)
                Transition("DWD1 maximum tree size cannot decrease.");
        }
        var validFrom = Scalars.UInt64(record.FieldSpan(5));
        var validUntil = Scalars.UInt64(record.FieldSpan(6));
        var checkpointTtl = Scalars.UInt64(record.FieldSpan(7));
        var leaseTtl = Scalars.UInt64(record.FieldSpan(8));
        if (validFrom == 0 || validUntil <= validFrom ||
            (requireActiveAtTransactionTime &&
                (transactionTimeUnixSeconds < validFrom || transactionTimeUnixSeconds >= validUntil)) ||
            checkpointTtl == 0 || leaseTtl == 0 ||
            delegation.MaximumTreeSize == 0 || delegation.MaximumTreeSize > 4294967296UL)
            throw new RecordException(RecordError.Expired,
                "DWD1 time or size limits are invalid at txNow.");
        Equal(record.FieldSpan(11), ComputeSubjectPolicy(record), "DWD1 subject policy hash");
        ValidatePredecessorHeads(predecessor,predecessorFinalHeads288);
        if (predecessor is null)
        {
            if (!CanonicalGrammar.IsZero(record.FieldSpan(12)))
                Invalid("Genesis DWD1 predecessor heads commitment must be exact zero32.");
        }
        else
        {
            Span<byte> headsPayload = stackalloc byte[8 + 288];
            BinaryPrimitives.WriteUInt64BigEndian(headsPayload,
                predecessor.Delegation.WitnessEpoch);
            predecessorFinalHeads288.CopyTo(headsPayload[8..]);
            Equal(record.FieldSpan(12), CanonicalGrammar.Sha256Domain(
                HeadsDomain,
                headsPayload), "DWD1 predecessor heads commitment");
        }
        var descriptors = ParseDescriptors(record.FieldSpan(14));
        Span<byte> setRootPayload = stackalloc byte[8 + 1 + 464];
        record.FieldSpan(4).CopyTo(setRootPayload);
        setRootPayload[8] = 4;
        record.FieldSpan(14).CopyTo(setRootPayload[9..]);
        Equal(record.FieldSpan(15), CanonicalGrammar.Sha256Domain(
            SetRootDomain,
            setRootPayload), "DWD1 witness set root");
        Reference(CanonicalGrammar.DecodeReference(record.FieldSpan(16)),
            root.CurrentTransitionReference, "DWD1 ReleaseRoot transition");
        var retained = ValidateWitnessContinuity(predecessor, descriptors);
        if (predecessor is not null && retained < 3)
            Transition("A DWD1 successor may replace at most one witness.");
        var core = DwdCore(record);
        VerifySignature(record.FieldSpan(17), SignatureInput(DelegationDomain, core),
            root.CurrentEd25519PublicKey.Span);

        for (var index = 0; index < 4; index++)
        {
            var descriptor = descriptors[index];
            var successorPayload = new byte[889];
            core.CopyTo(successorPayload, 0);
            descriptor.WitnessId.Span.CopyTo(successorPayload.AsSpan(857));
            VerifySignature(record.FieldSpan(18 + index),
                SignatureInput(SuccessorDomain, successorPayload),
                descriptor.Ed25519PublicKey.Span);
        }
        return new WitnessDelegationRelativeFact(delegation, root, descriptors);
    }

    private static int ValidateWitnessContinuity(
        WitnessDelegationRelativeFact? predecessor,
        IReadOnlyList<WitnessDescriptorRelative> descriptors)
    {
        if (predecessor is null) return 0;
        var retained = 0;
        foreach (var descriptor in descriptors)
        {
            var prior = predecessor.Descriptors.SingleOrDefault(value =>
                CanonicalGrammar.FixedEquals(value.WitnessId.Span, descriptor.WitnessId.Span));
            if (prior is null) continue;
            if (!CanonicalGrammar.FixedEquals(
                    prior.Ed25519PublicKey.Span,
                    descriptor.Ed25519PublicKey.Span))
                Transition("A retained witness ID changed its Ed25519 key.");
            retained++;
        }
        return retained;
    }

    private static void ValidatePredecessorHeads(
        WitnessDelegationRelativeFact? predecessor,
        ReadOnlySpan<byte> heads)
    {
        if(predecessor is null)
        {
            if(!CanonicalGrammar.IsZero(heads))
                Invalid("Genesis DWD1 predecessor heads must be the exact zero 288-byte tuple.");
            return;
        }
        for(var index=0;index<4;index++)
        {
            var row=heads.Slice(index*72,72);
            var descriptor=predecessor.Descriptors[index];
            Equal(row[..32],descriptor.WitnessId.Span,"DWD1 predecessor head witness ID");
            var treeSize=BinaryPrimitives.ReadUInt64BigEndian(row[32..40]);
            if(treeSize>predecessor.Delegation.MaximumTreeSize)
                Invalid("A DWD1 predecessor head exceeds the delegated maximum tree size.");
            if(treeSize==0)
                Equal(row[40..],WitnessTreeVerifier.EmptyRoot(
                    predecessor.Delegation.WitnessEpoch,
                    descriptor.WitnessId.Span,
                    predecessor.Delegation.MaximumTreeSize),
                    "DWD1 predecessor empty-tree root");
            else Nonzero(row[40..],"DWD1 predecessor tree root");
        }
    }

    private static WitnessDescriptorRelative[] ParseDescriptors(ReadOnlySpan<byte> rows)
    {
        var output = new WitnessDescriptorRelative[4];
        ReadOnlySpan<byte> previousId = default;
        for (var index = 0; index < 4; index++)
        {
            var row = rows.Slice(index * 116, 116);
            if (index != 0 && Compare(previousId, row[..32]) >= 0)
                Invalid("DWD1 witness descriptors are not strictly ID-sorted.");
            previousId = row[..32];
            if (CanonicalGrammar.IsZero(row[..32]) ||
                CanonicalGrammar.IsZero(row.Slice(32, 32)) ||
                row[65] != 0 ||
                BinaryPrimitives.ReadUInt16BigEndian(row.Slice(82, 2)) == 0 ||
                CanonicalGrammar.IsZero(row.Slice(84, 32)))
                Invalid("A DWD1 witness descriptor is malformed.");
            if (row[64] == (byte)WitnessEndpointKind.Ipv4)
            {
                if (row.Slice(70, 12).IndexOfAnyExcept((byte)0) >= 0)
                    Invalid("A DWD1 IPv4 descriptor has a nonzero address tail.");
            }
            else if (row[64] != (byte)WitnessEndpointKind.Ipv6)
                Invalid("A DWD1 witness endpoint kind is unknown.");
            output[index] = new WitnessDescriptorRelative(row);
        }
        return output;
    }

    private static byte[] ComputeSubjectPolicy(OwnedRecord record)
    {
        Span<byte> payload = stackalloc byte[63];
        var offset = 0;
        record.FieldSpan(1).CopyTo(payload); offset += 16;
        BinaryPrimitives.WriteUInt16BigEndian(payload[offset..], 1); offset += 2;
        payload[offset++] = 1;
        record.FieldSpan(10).CopyTo(payload[offset..]); offset += 8;
        payload[offset++] = 4;
        for (ushort kind = 1; kind <= 4; kind++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(payload[offset..], kind);
            offset += 2;
        }
        payload[offset++] = 4;
        payload[offset++] = 4;
        payload[offset++] = 1;
        record.FieldSpan(7).CopyTo(payload[offset..]); offset += 8;
        record.FieldSpan(8).CopyTo(payload[offset..]); offset += 8;
        record.FieldSpan(9).CopyTo(payload[offset..]); offset += 8;
        if (offset != payload.Length) throw new InvalidOperationException("DWD1 policy width drifted.");
        return CanonicalGrammar.Sha256Domain(PolicyDomain, payload);
    }

    private static byte[] DwdCore(OwnedRecord record)
    {
        var definition = record.Definition with
        {
            Fields = record.Definition.Fields.Take(16).ToArray(),
            MinimumLength = 857,
            MaximumLength = 857,
            OmittedSigningFieldIndexes = new HashSet<int>()
        };
        return CanonicalGrammar.Encode(definition,
            Enumerable.Range(1, 16).Select(tag => (ReadOnlyMemory<byte>)record.FieldCopy(tag)).ToArray());
    }

    private static ReleaseRootAuthorityTuple BuildAuthorityTuple(
        ReleaseRootRelativeFact root,
        WitnessDelegationRelativeFact latestDelegation,
        WitnessTerminationRelativeFact? termination)
    {
        var genesisReference = CanonicalGrammar.ComputeReference(
            ArtifactType.Rrm1,
            root.Manifest.CanonicalBytes.Span);
        var latestDwdReference = CanonicalGrammar.ComputeReference(
            ArtifactType.Dwd1,
            latestDelegation.Delegation.CanonicalBytes.Span);
        var terminalKrfReference = root.PendingTerminalRevocation is null
            ? default
            : CanonicalGrammar.ComputeReference(
                ArtifactType.Krf1,
                root.PendingTerminalRevocation.CanonicalBytes.Span);
        var terminalDwtReference = termination is null
            ? default
            : CanonicalGrammar.ComputeReference(
                ArtifactType.Dwt1,
                termination.Termination.CanonicalBytes.Span);

        var chainPayload = new byte[38 + 2 + checked(root.Transitions.Count * 38) + 38];
        var chainOffset = 0;
        CanonicalGrammar.EncodeReference(genesisReference).CopyTo(chainPayload, chainOffset);
        chainOffset += 38;
        BinaryPrimitives.WriteUInt16BigEndian(chainPayload.AsSpan(chainOffset),
            checked((ushort)root.Transitions.Count));
        chainOffset += 2;
        foreach (var transition in root.Transitions)
        {
            CanonicalGrammar.EncodeReference(transition).CopyTo(chainPayload, chainOffset);
            chainOffset += 38;
        }
        CanonicalGrammar.EncodeReference(latestDwdReference).CopyTo(chainPayload, chainOffset);
        var checkpoint = CanonicalGrammar.Sha256Domain(RootChainDomain, chainPayload);

        var tuple = new byte[282];
        var offset = 0;
        void Append(ReadOnlySpan<byte> value)
        {
            value.CopyTo(tuple.AsSpan(offset));
            offset += value.Length;
        }
        Append(CanonicalGrammar.EncodeReference(genesisReference));
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(offset), root.CurrentGeneration); offset += 8;
        Append(root.CurrentEd25519PublicKey.Span);
        Append(CanonicalGrammar.EncodeReference(root.CurrentTransitionReference));
        Append(CanonicalGrammar.EncodeReference(terminalKrfReference));
        tuple[offset++] = termination is null ? (byte)0 : (byte)1;
        tuple[offset++] = 0;
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(offset),
            latestDelegation.Delegation.DelegationGeneration); offset += 8;
        Append(CanonicalGrammar.EncodeReference(latestDwdReference));
        BinaryPrimitives.WriteUInt64BigEndian(tuple.AsSpan(offset),
            latestDelegation.Delegation.WitnessEpoch); offset += 8;
        BinaryPrimitives.WriteUInt16BigEndian(tuple.AsSpan(offset),
            checked((ushort)root.Transitions.Count)); offset += 2;
        Append(checkpoint);
        Append(CanonicalGrammar.EncodeReference(terminalDwtReference));
        if (offset != tuple.Length) throw new InvalidOperationException("ReleaseRoot authority tuple width drifted.");
        return new ReleaseRootAuthorityTuple(tuple);
    }

    private static QuorumLease VerifyFreshLeaseTail(
        ReadOnlySpan<byte> canonical,
        ReleaseRootRelativeFact root,
        WitnessDelegationRelativeFact latestDelegation,
        ReleaseRootAuthorityTuple tuple,
        ulong transactionTimeUnixSeconds)
    {
        var lease = CutoverCodec.DecodeQuorumLease(canonical);
        var record = lease.Record;
        Equal(record.FieldSpan(1), root.Manifest.NetworkId.Span, "DCL1 network");
        Nonzero(record.FieldSpan(2), "DCL1 deployment subject");
        _ = CanonicalGrammar.DecodeReference(record.FieldSpan(4));
        var latestDwdReference = CanonicalGrammar.ComputeReference(
            ArtifactType.Dwd1,
            latestDelegation.Delegation.CanonicalBytes.Span);
        Reference(CanonicalGrammar.DecodeReference(record.FieldSpan(5)),
            latestDwdReference, "DCL1 DWD1");
        var authorityHead = CanonicalGrammar.Sha256Domain(
            RootAuthorityHeadDomain,
            tuple.CanonicalTuple.Span);
        Equal(record.FieldSpan(6), authorityHead, "DCL1 ReleaseRoot authority head");
        Equal(record.FieldSpan(7), latestDelegation.Delegation.Record.FieldSpan(15),
            "DCL1 witness set root");
        if (Scalars.UInt64(record.FieldSpan(8)) != latestDelegation.Delegation.WitnessEpoch)
            Invalid("DCL1 witness epoch does not match the latest DWD1.");
        Nonzero(record.FieldSpan(9), "DCL1 query nonce");
        var issuedAt = Scalars.UInt64(record.FieldSpan(12));
        var expiresAt = Scalars.UInt64(record.FieldSpan(13));
        var maximumLeaseTtl = Scalars.UInt64(latestDelegation.Delegation.Record.FieldSpan(8));
        if (issuedAt == 0 || expiresAt <= issuedAt ||
            transactionTimeUnixSeconds < issuedAt || transactionTimeUnixSeconds >= expiresAt ||
            expiresAt - issuedAt > maximumLeaseTtl ||
            issuedAt < latestDelegation.Delegation.ValidFromUnixSeconds ||
            expiresAt > latestDelegation.Delegation.ValidUntilUnixSeconds)
            throw new RecordException(RecordError.Expired,
                "DCL1 is not a fresh lease inside the latest DWD1 policy window.");

        var blob = record.FieldSpan(11);
        var cursor = 0;
        var references = new byte[114];
        ReadOnlySpan<byte> previousWitnessId = default;
        for (var index = 0; index < 3; index++)
        {
            if (cursor > blob.Length - 4) Invalid("DCL1 has a truncated DHL1 length prefix.");
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(blob.Slice(cursor, 4)));
            cursor += 4;
            if (length is < 710 or > 1734 || cursor > blob.Length - length)
                Invalid("DCL1 has an invalid bounded DHL1 row.");
            var headLease = CutoverCodec.DecodeHeadLease(blob.Slice(cursor, length));
            cursor += length;
            var head = headLease.Record;
            for (var tag = 1; tag <= 4; tag++)
                Equal(head.FieldSpan(tag), record.FieldSpan(tag), $"DCL1/DHL1 common field {tag}");
            Equal(head.FieldSpan(5), record.FieldSpan(7), "DCL1/DHL1 witness set root");
            Equal(head.FieldSpan(6), record.FieldSpan(8), "DCL1/DHL1 witness epoch");
            WitnessAuthorityBinding.Verify(
                head.FieldSpan(7), Scalars.UInt64(head.FieldSpan(8)), head.FieldSpan(9),
                head.FieldSpan(10), head.FieldSpan(11)[0], head.FieldSpan(12),
                record.FieldSpan(5), root.CurrentGeneration,
                CanonicalGrammar.EncodeReference(root.CurrentTransitionReference), new byte[38],
                expectedTerminalState: false, authorityHead);
            var witnessId = head.FieldSpan(13);
            if (index != 0 && Compare(previousWitnessId, witnessId) >= 0)
                Invalid("DCL1 DHL1 rows are not strictly witness-ID sorted.");
            previousWitnessId = witnessId;
            WitnessDescriptorRelative? descriptor = null;
            foreach (var candidate in latestDelegation.Descriptors)
                if (CanonicalGrammar.FixedEquals(candidate.WitnessId.Span, witnessId))
                {
                    descriptor = candidate;
                    break;
                }
            if (descriptor is null)
                Invalid("A DCL1 DHL1 signer is outside the latest DWD1.");
            var priorSize = Scalars.UInt64(head.FieldSpan(14));
            var currentSize = Scalars.UInt64(head.FieldSpan(16));
            if (priorSize > currentSize || currentSize > latestDelegation.Delegation.MaximumTreeSize ||
                (priorSize == currentSize &&
                    !CanonicalGrammar.FixedEquals(head.FieldSpan(15), head.FieldSpan(17))))
                Invalid("A DHL1 tree head violates its monotonic tree-size fence.");
            WitnessTreeVerifier.VerifyConsistency(
                priorSize,
                head.FieldSpan(15),
                currentSize,
                head.FieldSpan(17),
                head.FieldSpan(19),
                WitnessTreeVerifier.EmptyRoot(
                    Scalars.UInt64(head.FieldSpan(6)),
                    head.FieldSpan(13),
                    latestDelegation.Delegation.MaximumTreeSize));
            Equal(head.FieldSpan(20), record.FieldSpan(9), "DCL1/DHL1 query nonce");
            var headIssuedAt = Scalars.UInt64(head.FieldSpan(21));
            var headExpiresAt = Scalars.UInt64(head.FieldSpan(22));
            if (headIssuedAt == 0 || headExpiresAt <= headIssuedAt ||
                headIssuedAt > issuedAt || headExpiresAt < expiresAt ||
                headExpiresAt - headIssuedAt > maximumLeaseTtl)
                throw new RecordException(RecordError.Expired,
                    "A DCL1 DHL1 time window does not cover the quorum lease.");
            VerifySignature(
                head.FieldSpan(23),
                CanonicalGrammar.GetSigningBytes(head, HeadLeaseDomain),
                descriptor!.Ed25519PublicKey.Span);
            CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                    ArtifactType.Dhl1,
                    head.CanonicalSpan))
                .CopyTo(references, index * 38);
        }
        if (cursor != blob.Length) Invalid("DCL1 contains trailing or unconsumed DHL1 bytes.");
        var digestPayload = new byte[224];
        var digestOffset = 0;
        foreach (var tag in new[] { 2, 3, 4, 9 })
        {
            record.FieldSpan(tag).CopyTo(digestPayload.AsSpan(digestOffset));
            digestOffset += record.FieldSpan(tag).Length;
        }
        references.CopyTo(digestPayload, digestOffset);
        Equal(record.FieldSpan(14), CanonicalGrammar.Sha256Domain(
            LeaseDigestDomain,
            digestPayload), "DCL1 lease digest");
        return lease;
    }

    private static void PreflightLeaseRows(ReadOnlySpan<byte> canonical)
    {
        var lease = CutoverCodec.DecodeQuorumLease(canonical);
        var blob = lease.Record.FieldSpan(11);
        var cursor = 0;
        for (var index = 0; index < 3; index++)
        {
            if (cursor > blob.Length - 4) Invalid("DCL1 has a truncated DHL1 length prefix.");
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(blob.Slice(cursor, 4)));
            cursor += 4;
            if (length is < 710 or > 1734 || cursor > blob.Length - length)
                Invalid("DCL1 has an invalid bounded DHL1 row.");
            _ = CutoverCodec.DecodeHeadLease(blob.Slice(cursor, length));
            cursor += length;
        }
        if (cursor != blob.Length) Invalid("DCL1 contains trailing or unconsumed DHL1 bytes.");
    }

    private static bool SameReference(ArtifactReference left, ArtifactReference right) =>
        left.Type == right.Type &&
        left.CanonicalLength == right.CanonicalLength &&
        CanonicalGrammar.FixedEquals(left.CanonicalHash.Span, right.CanonicalHash.Span);

    private static byte[] RestoreFingerprint(
        ReadOnlySpan<byte> manifest,
        IReadOnlyList<byte[]> transitions,
        IReadOnlyList<byte[]> delegations,
        IReadOnlyList<byte[]> predecessorHeads,
        ReadOnlySpan<byte> tail)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        void Append(ReadOnlySpan<byte> value)
        {
            Span<byte> length = stackalloc byte[8];
            BinaryPrimitives.WriteUInt64BigEndian(length, checked((ulong)value.Length));
            hash.AppendData(length);
            hash.AppendData(value);
        }
        Append(manifest);
        Span<byte> count = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(count, checked((ushort)transitions.Count));
        hash.AppendData(count);
        foreach (var transition in transitions) Append(transition);
        BinaryPrimitives.WriteUInt16BigEndian(count, checked((ushort)delegations.Count));
        hash.AppendData(count);
        for (var index = 0; index < delegations.Count; index++)
        {
            Append(delegations[index]);
            Append(predecessorHeads[index]);
        }
        Append(tail);
        return hash.GetHashAndReset();
    }

    private sealed record RestoreReplayState(
        byte[] ClosureFingerprint,
        byte[] AuthorityTuple,
        ulong RootGeneration,
        ulong DwdGeneration,
        bool Terminal);

    private static void BindRootTransition(
        OwnedRecord record,
        ReleaseRootRelativeFact current,
        ArtifactReference predecessor,
        KeyAction expectedAction)
    {
        Equal(record.FieldSpan(1), current.Manifest.NetworkId.Span, "ReleaseRoot transition network");
        if (record.FieldSpan(2)[0] != (byte)KeyScope.ReleaseRoot ||
            !CanonicalGrammar.IsZero(record.FieldSpan(3)) ||
            Scalars.UInt64(record.FieldSpan(4)) != 0 ||
            Scalars.UInt64(record.FieldSpan(5)) != checked(current.CurrentGeneration + 1))
            Invalid("The ReleaseRoot transition scope, account tuple, or generation is invalid.");
        Reference(predecessor, current.CurrentTransitionReference,
            "ReleaseRoot transition predecessor");
        Equal(record.FieldSpan(7), ComputeRootKeyHash(
            current.Manifest.NetworkId.Span,
            current.CurrentEd25519PublicKey.Span), "ReleaseRoot old key hash");
        var actionTag = record.Definition.Magic == ProtocolMagic.KRT1 ? 10 : 9;
        if (record.FieldSpan(actionTag)[0] != (byte)expectedAction)
            Invalid("The ReleaseRoot transition action does not match its record type.");
        if (current.Transitions.Count >= 64)
            Transition("ReleaseRoot transition 65 is terminal chain exhaustion.");
    }

    private static byte[] ComputeRootKeyHash(ReadOnlySpan<byte> network, ReadOnlySpan<byte> publicKey)
    {
        Span<byte> payload = stackalloc byte[89];
        network.CopyTo(payload);
        payload[16] = (byte)KeyScope.ReleaseRoot;
        payload.Slice(17, 40).Clear();
        publicKey.CopyTo(payload[57..]);
        return CanonicalGrammar.Sha256Domain(KeyHashDomain, payload);
    }

    private static byte[] SignatureInput(string domain, ReadOnlySpan<byte> payload)
    {
        var domainBytes = System.Text.Encoding.ASCII.GetBytes(domain);
        var output = new byte[2 + domainBytes.Length + 2 + 4 + payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(output, checked((ushort)domainBytes.Length));
        domainBytes.CopyTo(output, 2);
        var offset = 2 + domainBytes.Length;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset),
            ArtifactRegistry.IdentityAuthV1Ed25519);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 2), checked((uint)payload.Length));
        payload.CopyTo(output.AsSpan(offset + 6));
        return output;
    }

    private static void Effective(ReadOnlySpan<byte> value, ulong now)
    {
        var effective = Scalars.UInt64(value);
        if (effective == 0 || now < effective)
            throw new RecordException(RecordError.Expired,
                "The ReleaseRoot transition is not effective at txNow.");
    }

    private static int Compare(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        for (var index = 0; index < Math.Min(left.Length, right.Length); index++)
        {
            var comparison = left[index].CompareTo(right[index]);
            if (comparison != 0) return comparison;
        }
        return left.Length.CompareTo(right.Length);
    }

    private static void VerifySignature(
        ReadOnlySpan<byte> signature,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> publicKey)
    {
        if (signature.Length != 64 || publicKey.Length != 32 ||
            !PublicKeyAuth.VerifyDetached(signature.ToArray(), message.ToArray(), publicKey.ToArray()))
            throw new RecordException(RecordError.InvalidSignature,
                "A relative ReleaseRoot or witness signature is invalid.");
    }

    private static void Reference(
        ArtifactReference actual,
        ArtifactReference expected,
        string name)
    {
        if (actual.Type != expected.Type || actual.CanonicalLength != expected.CanonicalLength ||
            !CanonicalGrammar.FixedEquals(
                actual.CanonicalHash.Span,
                expected.CanonicalHash.Span))
            Invalid($"The {name} does not match.");
    }

    private static void Nonzero(ReadOnlySpan<byte> value, string name)
    {
        if (CanonicalGrammar.IsZero(value)) Invalid($"The {name} is zero.");
    }

    private static void Equal(ReadOnlySpan<byte> actual, ReadOnlySpan<byte> expected, string name)
    {
        if (!CanonicalGrammar.FixedEquals(actual, expected)) Invalid($"The {name} does not match.");
    }

    private static void Revoked(string message) =>
        throw new RecordException(RecordError.Revoked, message);

    private static void Transition(string message) =>
        throw new RecordException(RecordError.InvalidTransition, message);

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);
}
