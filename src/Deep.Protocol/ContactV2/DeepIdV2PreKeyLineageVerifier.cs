using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Checks the exact XPI1 predecessor link before a replica admits a new
/// inventory epoch. The predecessor must come from the replica's own durable,
/// already-authorized state; caller-supplied predecessor bytes are not authority.
/// </summary>
public static class DeepIdV2PreKeyLineageVerifier
{
    public static bool RuntimeActivation => false;

    /// <summary>Verifies an unchanged signed service or its exact immediate
    /// same-device successor. The caller owns the independent expected device
    /// key/scope; this proves no currentness, inventory commit or dispatch.</summary>
    public static void VerifyServiceTransition(ParsedXps1V2 candidate,
        ParsedXps1V2 durablePredecessor, ReadOnlySpan<byte> deviceSigningPublicKey)
    {
        ArgumentNullException.ThrowIfNull(candidate); ArgumentNullException.ThrowIfNull(durablePredecessor);
        var old = durablePredecessor;
        foreach (var tag in new[] { 1, 2, 3, 4, 7, 8, 9 })
            if (!Fixed(old.Field(tag).Span, candidate.Field(tag).Span))
                throw new CryptographicException("Contact prekey succession changed its service identity or policy.");
        DeepIdV2PreKeyServiceCodec.VerifyDeviceSignature(old, deviceSigningPublicKey);
        DeepIdV2PreKeyServiceCodec.VerifyDeviceSignature(candidate, deviceSigningPublicKey);
        if (Fixed(old.CanonicalBytes.Span, candidate.CanonicalBytes.Span)) return;
        var generation = U64(old.Field(5).Span);
        if (generation == ulong.MaxValue || U64(candidate.Field(5).Span) != generation + 1 ||
            !Fixed(candidate.Field(6).Span, SHA256.HashData(old.CanonicalBytes.Span)) ||
            U64(candidate.Field(10).Span) < U64(old.Field(10).Span) || U64(candidate.Field(11).Span) <= U64(old.Field(11).Span))
            throw new CryptographicException("Contact prekey succession does not advance its exact signed predecessor.");
    }

    /// <summary>Anchors an exact bounded set of historical intermediates in
    /// the supplied authenticated predecessor. Every hop remains immediate;
    /// this proves no service currentness, inventory commitment or dispatch.</summary>
    public static void VerifyServiceHistory(ParsedXps1V2 candidate,
        ParsedXps1V2 durablePredecessor, IReadOnlyList<ParsedXps1V2> intermediates,
        ReadOnlySpan<byte> deviceSigningPublicKey)
    {
        ArgumentNullException.ThrowIfNull(candidate); ArgumentNullException.ThrowIfNull(durablePredecessor);
        ArgumentNullException.ThrowIfNull(intermediates);
        if (intermediates.Count > DeepIdV2ResolverClosureCodec.MaximumPreKeyServiceHistoryEntries)
            throw new CryptographicException("Contact prekey history exceeds its bounded support.");
        if (intermediates.Count == 0)
        {
            VerifyServiceTransition(candidate, durablePredecessor, deviceSigningPublicKey); return;
        }
        if (Fixed(candidate.CanonicalBytes.Span, durablePredecessor.CanonicalBytes.Span))
        {
            throw new CryptographicException("An unchanged service cannot consume historical witnesses.");
        }
        var oldGeneration = U64(durablePredecessor.Field(5).Span);
        var nextGeneration = U64(candidate.Field(5).Span);
        if (nextGeneration <= oldGeneration || nextGeneration - oldGeneration != (ulong)intermediates.Count + 1)
            throw new CryptographicException("Contact prekey history omits or adds an exact intermediate.");
        var ordered = intermediates.Select(value => value ?? throw new CryptographicException("A prekey history record is absent."))
            .OrderBy(value => U64(value.Field(5).Span)).ToArray();
        var previous = durablePredecessor;
        foreach (var item in ordered)
        {
            if (U64(item.Field(5).Span) <= oldGeneration || U64(item.Field(5).Span) >= nextGeneration)
                throw new CryptographicException("A prekey history witness is not a strict intermediate.");
            VerifyServiceTransition(item, previous, deviceSigningPublicKey); previous = item;
        }
        VerifyServiceTransition(candidate, previous, deviceSigningPublicKey);
    }

    public static void VerifySuccessor(ParsedXpi1V2 candidate,
        ParsedXpi1V2? durablePredecessor)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        var epoch = U64(candidate.Field(7).Span);
        if (durablePredecessor is null)
        {
            if (epoch != 1 || !IsZero(candidate.Field(8).Span))
                Reject("The first DID2 inventory must start at epoch one without a predecessor.");
            return;
        }

        // A new service has its own epoch namespace. Its signed XPS chain is
        // independently verified by the authoritative committer; these parsed
        // manifests alone are structural lineage, never that authority.
        var previousGeneration = U64(durablePredecessor.Field(5).Span);
        var generation = U64(candidate.Field(5).Span);
        if (generation != previousGeneration)
        {
            foreach (var tag in new[] { 1, 2, 3, 4 })
                if (!Fixed(candidate.Field(tag).Span, durablePredecessor.Field(tag).Span))
                    Reject("The DID2 inventory service successor changed its device scope.");
            if (previousGeneration == ulong.MaxValue || generation != previousGeneration + 1 ||
                epoch != 1 || !IsZero(candidate.Field(8).Span) ||
                Fixed(candidate.Field(6).Span, durablePredecessor.Field(6).Span))
                Reject("The DID2 inventory does not start the exact next service.");
            return;
        }
        var previousEpoch = U64(durablePredecessor.Field(7).Span);
        if (previousEpoch == 14 || epoch != previousEpoch + 1 ||
            !Fixed(candidate.Field(8).Span,
                durablePredecessor.ExactHash.Span))
            Reject("The DID2 inventory does not extend the exact durable predecessor.");

        // An XPS1 service generation has one account-owned responder device.
        // A new DMD1/DRS1 head may be witnessed by a successor, but the
        // service's identity and its signed policy cannot silently change.
        foreach (var tag in new[] { 1, 2, 3, 4, 5, 6 })
            if (!Fixed(candidate.Field(tag).Span,
                    durablePredecessor.Field(tag).Span))
                Reject("The DID2 inventory successor changed its service identity.");
    }

    private static ulong U64(ReadOnlySpan<byte> bytes) =>
        BinaryPrimitives.ReadUInt64BigEndian(bytes);

    private static bool IsZero(ReadOnlySpan<byte> bytes) =>
        bytes.IndexOfAnyExcept((byte)0) < 0;

    private static bool Fixed(ReadOnlySpan<byte> left,
        ReadOnlySpan<byte> right) =>
        left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(left, right);

    private static void Reject(string message) => throw ApplicationCoreFormat.Error(
        ApplicationCoreValidationStage.CryptographicVerification,
        ApplicationCoreRejection.InvalidLineage, message);
}
