using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxAuthority;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

public delegate ValueTask ProductionMailboxPss2OldIssuerSigner(
    ProductionMailboxPss2OldIssuerSigningRequest request,
    Memory<byte> signatureDestination,
    CancellationToken cancellationToken);

public delegate ValueTask ProductionMailboxPss2CurrentIssuerSigner(
    ProductionMailboxPss2CurrentIssuerSigningRequest request,
    Memory<byte> signatureDestination,
    CancellationToken cancellationToken);

public sealed class ProductionMailboxPss2OldIssuerSigningRequest
{
    private readonly byte[] _signingBytes;
    private readonly byte[] _expectedPublicKey;

    internal ProductionMailboxPss2OldIssuerSigningRequest(
        ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> expectedPublicKey)
    {
        _signingBytes = signingBytes.ToArray();
        _expectedPublicKey = expectedPublicKey.ToArray();
    }

    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();
    public ReadOnlyMemory<byte> ExpectedIssuerEd25519PublicKey => _expectedPublicKey.ToArray();
    internal ReadOnlySpan<byte> TrustedSigningBytes => _signingBytes;
    internal ReadOnlySpan<byte> TrustedExpectedPublicKey => _expectedPublicKey;
    internal void Clear()
    {
        CryptographicOperations.ZeroMemory(_signingBytes);
        CryptographicOperations.ZeroMemory(_expectedPublicKey);
    }
}

public sealed class ProductionMailboxPss2CurrentIssuerSigningRequest
{
    private readonly byte[] _signingBytes;
    private readonly byte[] _expectedPublicKey;

    internal ProductionMailboxPss2CurrentIssuerSigningRequest(
        ReadOnlySpan<byte> signingBytes, ReadOnlySpan<byte> expectedPublicKey)
    {
        _signingBytes = signingBytes.ToArray();
        _expectedPublicKey = expectedPublicKey.ToArray();
    }

    public ReadOnlyMemory<byte> SigningBytes => _signingBytes.ToArray();
    public ReadOnlyMemory<byte> ExpectedIssuerEd25519PublicKey => _expectedPublicKey.ToArray();
    internal ReadOnlySpan<byte> TrustedSigningBytes => _signingBytes;
    internal ReadOnlySpan<byte> TrustedExpectedPublicKey => _expectedPublicKey;
    internal void Clear()
    {
        CryptographicOperations.ZeroMemory(_signingBytes);
        CryptographicOperations.ZeroMemory(_expectedPublicKey);
    }
}

/// <summary>
/// High-level PSS2 authoring. Every semantic and route closure is verified with frozen placeholder
/// signatures before either typed key-custody callback is invoked. The signed bytes are then run
/// through the production verifier; no unverified artifact or signing transcript is returned.
/// </summary>
public static class ProductionMailboxSelectionSuccessorAuthoring
{
    private const byte PlaceholderSignatureByte = 0xA5;

    public static async ValueTask<VerifiedProductionMailboxRouteSelectionTransition> AuthorDirectAsync(
        ProductionMailboxSelectionSuccessorV2Proof unsignedDraft,
        ReadOnlyMemory<byte> canonicalFreshRouteCertificate,
        ReadOnlyMemory<byte> canonicalTransitionContext,
        ReadOnlyMemory<byte> canonicalRouteAuthorization,
        ReadOnlyMemory<byte> canonicalRevocationCheckpoint,
        VerifiedProductionMailboxAuthority oldAuthority,
        VerifiedProductionMailboxTopology oldTopology,
        VerifiedProductionMailboxAuthority currentAuthority,
        VerifiedProductionMailboxRevocationSnapshot currentRevocations,
        VerifiedProductionMailboxTopology currentTopology,
        ProductionMailboxSelectionSuccessorVerificationContext selectionContext,
        ProductionMailboxRouteSelectionTransitionVerificationContext routeContext,
        ProductionMailboxPss2OldIssuerSigner oldIssuerSigner,
        ProductionMailboxPss2CurrentIssuerSigner currentIssuerSigner,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(oldIssuerSigner);
        ArgumentNullException.ThrowIfNull(currentIssuerSigner);
        cancellationToken.ThrowIfCancellationRequested();
        var frozenDraft = ProductionMailboxSelectionSuccessorV2Codec.FreezeUnsignedForAuthoring(
            unsignedDraft ?? throw new ArgumentNullException(nameof(unsignedDraft)));
        if (frozenDraft.Selection.Mode != ProductionMailboxSelectionSuccessorMode.DirectPromotion)
            throw new ProductionMailboxSelectionSuccessorException(
                ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "Direct PSS2 authoring requires DirectPromotion mode.");
        var frozenSelectionContext = Freeze(selectionContext);
        var frozenRouteContext = Freeze(routeContext);
        var dummyBytes = ProductionMailboxSelectionSuccessorV2Codec.Encode(
            WithPlaceholderSignatures(frozenDraft, includeOld: true));
        var preflight = ProductionMailboxSelectionSuccessorVerifier
            .VerifyDirectRouteSelectionTransitionCore(dummyBytes,
                canonicalFreshRouteCertificate.Span, canonicalTransitionContext.Span,
                canonicalRouteAuthorization.Span, canonicalRevocationCheckpoint.Span,
                oldAuthority, oldTopology, currentAuthority, currentRevocations, currentTopology,
                frozenSelectionContext, frozenRouteContext, PlaceholderSignatureVerifier.Instance);

        var oldRequest = new ProductionMailboxPss2OldIssuerSigningRequest(
            ProductionMailboxSelectionSuccessorV2Codec.GetOldIssuerSigningBytes(frozenDraft),
            oldAuthority.Authority.MailboxIssuerEd25519PublicKey.Span);
        var currentRequest = new ProductionMailboxPss2CurrentIssuerSigningRequest(
            ProductionMailboxSelectionSuccessorV2Codec.GetCurrentIssuerSigningBytes(frozenDraft),
            currentAuthority.Authority.MailboxIssuerEd25519PublicKey.Span);
        var oldSignature = new byte[ProductionMailboxSelectionSuccessorConstants.Ed25519SignatureLength];
        var currentSignature = new byte[ProductionMailboxSelectionSuccessorConstants.Ed25519SignatureLength];
        byte[]? frozenOldSignature = null;
        byte[]? frozenCurrentSignature = null;
        try
        {
            await oldIssuerSigner(oldRequest, oldSignature, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            RequireSignature(oldSignature, "old issuer");
            frozenOldSignature = oldSignature.ToArray();
            CryptographicOperations.ZeroMemory(oldSignature);
            VerifySignature(oldRequest.TrustedExpectedPublicKey, oldRequest.TrustedSigningBytes,
                frozenOldSignature, "old issuer");
            await currentIssuerSigner(currentRequest, currentSignature, cancellationToken).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            RequireSignature(currentSignature, "current issuer");
            frozenCurrentSignature = currentSignature.ToArray();
            CryptographicOperations.ZeroMemory(currentSignature);
            VerifySignature(currentRequest.TrustedExpectedPublicKey,
                currentRequest.TrustedSigningBytes, frozenCurrentSignature, "current issuer");
            var signed = WithSignatures(frozenDraft, frozenOldSignature, frozenCurrentSignature);
            var signedBytes = ProductionMailboxSelectionSuccessorV2Codec.Encode(signed);
            return ProductionMailboxSelectionSuccessorVerifier.VerifyDirectRouteSelectionTransition(
                signedBytes, preflight.CanonicalRouteCertificate.Span,
                preflight.CanonicalTransitionContext.Span, preflight.CanonicalRouteAuthorization.Span,
                preflight.CanonicalRevocationCheckpoint.Span, oldAuthority, oldTopology,
                currentAuthority, currentRevocations, currentTopology,
                frozenSelectionContext, frozenRouteContext);
        }
        finally
        {
            oldRequest.Clear();
            currentRequest.Clear();
            CryptographicOperations.ZeroMemory(oldSignature);
            CryptographicOperations.ZeroMemory(currentSignature);
            if (frozenOldSignature is not null)
                CryptographicOperations.ZeroMemory(frozenOldSignature);
            if (frozenCurrentSignature is not null)
                CryptographicOperations.ZeroMemory(frozenCurrentSignature);
        }
    }

    public static async ValueTask<VerifiedProductionMailboxRouteSelectionTransition> AuthorOfflineAsync(
        ProductionMailboxSelectionSuccessorV2Proof unsignedDraft,
        ReadOnlyMemory<byte> canonicalNewAuthority,
        ReadOnlyMemory<byte> canonicalNewRevocationSnapshot,
        ReadOnlyMemory<byte> canonicalNewTopology,
        ReadOnlyMemory<byte> canonicalOldSelection,
        ReadOnlyMemory<byte> canonicalNewCurrentSelection,
        ReadOnlyMemory<byte> canonicalNewNextSelection,
        ReadOnlyMemory<byte> canonicalFreshRouteCertificate,
        ReadOnlyMemory<byte> canonicalTransitionContext,
        ReadOnlyMemory<byte> canonicalRouteAuthorization,
        ReadOnlyMemory<byte> canonicalRevocationCheckpoint,
        VerifiedProductionMailboxAuthority oldAuthority,
        VerifiedProductionMailboxTopology oldTopology,
        ProductionMailboxOfflineCheckpointClosureVerificationContext selectionContext,
        ProductionMailboxRouteSelectionTransitionVerificationContext routeContext,
        ProductionMailboxPss2CurrentIssuerSigner currentIssuerSigner,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(currentIssuerSigner);
        cancellationToken.ThrowIfCancellationRequested();
        var frozenDraft = ProductionMailboxSelectionSuccessorV2Codec.FreezeUnsignedForAuthoring(
            unsignedDraft ?? throw new ArgumentNullException(nameof(unsignedDraft)));
        if (frozenDraft.Selection.Mode != ProductionMailboxSelectionSuccessorMode.OfflineCheckpoint)
            throw new ProductionMailboxSelectionSuccessorException(
                ProductionMailboxSelectionSuccessorError.InvalidTransitionMode,
                "Offline PSS2 authoring requires OfflineCheckpoint mode.");
        var frozenSelectionContext = Freeze(selectionContext);
        var frozenRouteContext = Freeze(routeContext);
        var dummyBytes = ProductionMailboxSelectionSuccessorV2Codec.Encode(
            WithPlaceholderSignatures(frozenDraft, includeOld: false));
        var preflight = ProductionMailboxSelectionSuccessorVerifier
            .VerifyOfflineRouteSelectionTransitionClosureCore(dummyBytes,
                canonicalNewAuthority.Span, canonicalNewRevocationSnapshot.Span,
                canonicalNewTopology.Span, canonicalOldSelection.Span,
                canonicalNewCurrentSelection.Span, canonicalNewNextSelection.Span,
                canonicalFreshRouteCertificate.Span, canonicalTransitionContext.Span,
                canonicalRouteAuthorization.Span, canonicalRevocationCheckpoint.Span,
                oldAuthority, oldTopology, frozenSelectionContext, frozenRouteContext,
                PlaceholderSignatureVerifier.Instance);
        var closure = preflight.OfflineClosure ?? throw new InvalidOperationException(
            "Offline PSS2 preflight did not retain the complete closure.");
        var currentRequest = new ProductionMailboxPss2CurrentIssuerSigningRequest(
            ProductionMailboxSelectionSuccessorV2Codec.GetCurrentIssuerSigningBytes(frozenDraft),
            closure.Authority.Authority.MailboxIssuerEd25519PublicKey.Span);
        var currentSignature = new byte[ProductionMailboxSelectionSuccessorConstants.Ed25519SignatureLength];
        byte[]? frozenCurrentSignature = null;
        try
        {
            await currentIssuerSigner(currentRequest, currentSignature, cancellationToken)
                .ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            RequireSignature(currentSignature, "current issuer");
            frozenCurrentSignature = currentSignature.ToArray();
            CryptographicOperations.ZeroMemory(currentSignature);
            VerifySignature(currentRequest.TrustedExpectedPublicKey,
                currentRequest.TrustedSigningBytes, frozenCurrentSignature, "current issuer");
            var signed = WithSignatures(frozenDraft, new byte[64], frozenCurrentSignature);
            var signedBytes = ProductionMailboxSelectionSuccessorV2Codec.Encode(signed);
            return ProductionMailboxSelectionSuccessorVerifier.VerifyOfflineRouteSelectionTransitionClosure(
                signedBytes, closure.CanonicalNewAuthority.Span,
                closure.CanonicalNewRevocationSnapshot.Span, closure.CanonicalNewTopology.Span,
                closure.CanonicalOldSelection.Span, closure.CanonicalNewCurrentSelection.Span,
                closure.CanonicalNewNextSelection.Span, preflight.CanonicalRouteCertificate.Span,
                preflight.CanonicalTransitionContext.Span, preflight.CanonicalRouteAuthorization.Span,
                preflight.CanonicalRevocationCheckpoint.Span, oldAuthority, oldTopology,
                frozenSelectionContext, frozenRouteContext);
        }
        finally
        {
            currentRequest.Clear();
            CryptographicOperations.ZeroMemory(currentSignature);
            if (frozenCurrentSignature is not null)
                CryptographicOperations.ZeroMemory(frozenCurrentSignature);
        }
    }

    private static ProductionMailboxSelectionSuccessorV2Proof WithPlaceholderSignatures(
        ProductionMailboxSelectionSuccessorV2Proof value, bool includeOld)
    {
        var oldSignature = new byte[64];
        var currentSignature = new byte[64];
        if (includeOld) Array.Fill(oldSignature, PlaceholderSignatureByte);
        Array.Fill(currentSignature, PlaceholderSignatureByte);
        return WithSignatures(value, oldSignature, currentSignature);
    }

    private static ProductionMailboxSelectionSuccessorV2Proof WithSignatures(
        ProductionMailboxSelectionSuccessorV2Proof value,
        ReadOnlySpan<byte> oldSignature,
        ReadOnlySpan<byte> currentSignature) => value with
    {
        Selection = value.Selection with
        {
            OldIssuerSignature = oldSignature.ToArray(),
            NewIssuerSignature = currentSignature.ToArray()
        }
    };

    private static void RequireSignature(ReadOnlySpan<byte> signature, string name)
    {
        if (signature.Length != 64 || signature.IndexOfAnyExcept((byte)0) < 0)
            throw new CryptographicException($"PSS2 {name} callback returned no signature.");
    }

    private static void VerifySignature(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes,
        ReadOnlySpan<byte> signature, string name)
    {
        if (!new SodiumProductionMailboxSelectionSuccessorSignatureVerifier().Verify(
                publicKey, signingBytes, signature))
            throw new CryptographicException($"PSS2 {name} callback returned an invalid signature.");
    }

    private static ProductionMailboxSelectionSuccessorVerificationContext Freeze(
        ProductionMailboxSelectionSuccessorVerificationContext value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.ExpectedNetworkId.Length != 16 ||
            value.ExpectedMailboxOwnerEd25519PublicKey.Length != 32 ||
            value.ExpectedBlindedMailboxId.Length != 32 ||
            value.ExpectedBlindedPlacementId.Length != 32 ||
            value.PinnedMrXPublicKeySha256.Length != 32 ||
            value.ExpectedOldCanonicalSelectionHash.Length != 32)
            throw new ProductionMailboxSelectionSuccessorException(
                ProductionMailboxSelectionSuccessorError.InvalidField,
                "PSS2 direct authoring context has invalid fixed field lengths.");
        return value with
        {
            ExpectedNetworkId = value.ExpectedNetworkId.ToArray(),
            ExpectedMailboxOwnerEd25519PublicKey = value.ExpectedMailboxOwnerEd25519PublicKey.ToArray(),
            ExpectedBlindedMailboxId = value.ExpectedBlindedMailboxId.ToArray(),
            ExpectedBlindedPlacementId = value.ExpectedBlindedPlacementId.ToArray(),
            PinnedMrXPublicKeySha256 = value.PinnedMrXPublicKeySha256.ToArray(),
            ExpectedOldCanonicalSelectionHash = value.ExpectedOldCanonicalSelectionHash.ToArray()
        };
    }

    private static ProductionMailboxOfflineCheckpointClosureVerificationContext Freeze(
        ProductionMailboxOfflineCheckpointClosureVerificationContext value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.ExpectedNetworkId.Length != 16 || value.ExpectedMailboxOwnerEd25519PublicKey.Length != 32 ||
            value.ExpectedBlindedMailboxId.Length != 32 || value.ExpectedBlindedPlacementId.Length != 32 ||
            value.ExpectedSelectionInputCommitment.Length != 32 || value.PinnedMrXPublicKeySha256.Length != 32 ||
            value.ExpectedOldCanonicalAuthorityHash.Length != 32 ||
            value.ExpectedOldRevocationHeadHash.Length != 32 ||
            value.ExpectedOldRevocationSnapshotHash.Length != 32 ||
            value.ExpectedOldCanonicalTopologyHash.Length != 32 ||
            value.ExpectedOldCanonicalSelectionHash.Length != 32)
            throw new ProductionMailboxSelectionSuccessorException(
                ProductionMailboxSelectionSuccessorError.InvalidField,
                "PSS2 offline authoring context has invalid fixed field lengths.");
        return value with
        {
            ExpectedNetworkId = value.ExpectedNetworkId.ToArray(),
            ExpectedMailboxOwnerEd25519PublicKey = value.ExpectedMailboxOwnerEd25519PublicKey.ToArray(),
            ExpectedBlindedMailboxId = value.ExpectedBlindedMailboxId.ToArray(),
            ExpectedBlindedPlacementId = value.ExpectedBlindedPlacementId.ToArray(),
            ExpectedSelectionInputCommitment = value.ExpectedSelectionInputCommitment.ToArray(),
            PinnedMrXPublicKeySha256 = value.PinnedMrXPublicKeySha256.ToArray(),
            ExpectedOldCanonicalAuthorityHash = value.ExpectedOldCanonicalAuthorityHash.ToArray(),
            ExpectedOldRevocationHeadHash = value.ExpectedOldRevocationHeadHash.ToArray(),
            ExpectedOldRevocationSnapshotHash = value.ExpectedOldRevocationSnapshotHash.ToArray(),
            ExpectedOldCanonicalTopologyHash = value.ExpectedOldCanonicalTopologyHash.ToArray(),
            ExpectedOldCanonicalSelectionHash = value.ExpectedOldCanonicalSelectionHash.ToArray()
        };
    }

    private static ProductionMailboxRouteSelectionTransitionVerificationContext Freeze(
        ProductionMailboxRouteSelectionTransitionVerificationContext value)
    {
        ArgumentNullException.ThrowIfNull(value);
        if (value.ExpectedRouteDomainHash.Length != 32 ||
            value.CanonicalOldRouteOriginLkg.Length !=
                ProductionMailboxRouteContinuityConstants.CanonicalRouteOriginLkgLength)
            throw new ProductionMailboxSelectionSuccessorException(
                ProductionMailboxSelectionSuccessorError.InvalidField,
                "PSS2 route authoring context has invalid fixed field lengths.");
        return value with
        {
            ExpectedRouteDomainHash = value.ExpectedRouteDomainHash.ToArray(),
            CanonicalOldRouteOriginLkg = value.CanonicalOldRouteOriginLkg.ToArray()
        };
    }

    private sealed class PlaceholderSignatureVerifier : IProductionMailboxSelectionSuccessorSignatureVerifier
    {
        internal static PlaceholderSignatureVerifier Instance { get; } = new();

        public bool Verify(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> signingBytes,
            ReadOnlySpan<byte> signature) => publicKey.Length == 32 && signingBytes.Length > 0 &&
            signature.Length == 64 && signature.IndexOfAnyExcept(PlaceholderSignatureByte) < 0;
    }
}
