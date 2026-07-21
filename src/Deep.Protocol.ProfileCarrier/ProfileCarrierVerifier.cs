using Deep.Protocol.DeepExtension.Membership;

namespace Deep.Protocol.DeepExtension.SelfHostedProfiles;

public static class ProfileCarrierVerifier
{
    public static ProfileCarrierVerificationResult VerifyExact(
        ReadOnlySpan<byte> filePayload,
        ProfileCarrierVerificationOptions options,
        IMembershipSignatureVerifier verifier)
    {
        if (options is null || verifier is null)
        {
            throw ProfileCarrierErrors.InvalidInput();
        }

        try
        {
            return VerifyCore(
                filePayload,
                options,
                verifier,
                captureContinuity: false,
                continuityDisposed: null).Result;
        }
        catch (ProfileCarrierException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            throw ProfileCarrierErrors.Framing();
        }
    }

    internal static ProfileCarrierContinuity VerifyContinuityExact(
        ReadOnlySpan<byte> filePayload,
        ProfileCarrierVerificationOptions options,
        IMembershipSignatureVerifier verifier,
        Action<bool>? continuityDisposed = null)
    {
        if (options is null || verifier is null)
        {
            throw ProfileCarrierErrors.InvalidInput();
        }

        try
        {
            return VerifyCore(
                filePayload,
                options,
                verifier,
                captureContinuity: true,
                continuityDisposed).Continuity!;
        }
        catch (ProfileCarrierException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            throw ProfileCarrierErrors.Framing();
        }
    }

    internal static ProfileCarrierVerificationResult VerifyExactWithoutContinuity(
        ReadOnlySpan<byte> filePayload,
        ProfileCarrierVerificationOptions options,
        IMembershipSignatureVerifier verifier,
        Action<bool> continuityDisposed)
    {
        if (options is null || verifier is null || continuityDisposed is null)
        {
            throw ProfileCarrierErrors.InvalidInput();
        }

        try
        {
            return VerifyCore(
                filePayload,
                options,
                verifier,
                captureContinuity: false,
                continuityDisposed).Result;
        }
        catch (ProfileCarrierException)
        {
            throw;
        }
        catch (Exception exception) when (exception is not OutOfMemoryException)
        {
            throw ProfileCarrierErrors.Framing();
        }
    }

    private static VerifiedCarrier VerifyCore(
        ReadOnlySpan<byte> filePayload,
        ProfileCarrierVerificationOptions options,
        IMembershipSignatureVerifier verifier,
        bool captureContinuity,
        Action<bool>? continuityDisposed)
    {
        var components = ProfileCarrierFraming.Decode(filePayload);
        ValidateOrder(components);
        var canonical = filePayload.ToArray();
        var input = new ProfileCarrierAssemblyInput(
            components[0].Bytes,
            ProfileCarrierComposer.DecodeGenesisApprovals(components[1].Bytes),
            components[2].Bytes,
            components.Skip(3).Select(static value =>
                (ReadOnlyMemory<byte>)value.Bytes));
        var recomposed = ProfileCarrierComposer.ComposeExact(input, options, verifier);
        if (!recomposed.FilePayload.Span.SequenceEqual(canonical))
        {
            throw ProfileCarrierErrors.Framing();
        }

        var result = new ProfileCarrierVerificationResult(
            recomposed.FilePayloadSha256.Span,
            recomposed.Fingerprint,
            recomposed.MinimumProtocol,
            recomposed.MaximumProtocol,
            recomposed.ComponentCount,
            recomposed.BridgeCount);

        if (!captureContinuity)
        {
            return new(result, null);
        }

        byte[]? delegationCommitment = null;
        ProfileCarrierContinuity? continuity = null;
        var bridgeValues = new List<ProfileCarrierBridgeContinuity>(
            components.Count - ProfileCarrierLimits.RequiredNonBridgeComponents);
        var transferred = false;
        try
        {
            var delegation = MembershipContractCodec.DecodeSignedDelegation(
                components[2].Bytes);
            delegationCommitment = MembershipContractHash.Sha256(
                MembershipContractCodec.GetDelegationSigningBytes(delegation));
            foreach (var component in components.Skip(3))
            {
                var signed = MembershipContractCodec.DecodeSignedBridge(component.Bytes);
                bridgeValues.Add(new ProfileCarrierBridgeContinuity(
                    signed.Statement.Sequence,
                    MembershipContractHash.Sha256(
                        MembershipContractCodec.GetBridgeSigningBytes(signed.Statement))));
            }

            continuity = new ProfileCarrierContinuity(
                recomposed.Fingerprint,
                delegation.Sequence,
                delegationCommitment,
                bridgeValues.ToArray(),
                continuityDisposed);
            var verifiedCarrier = new VerifiedCarrier(result, continuity);
            transferred = true;
            return verifiedCarrier;
        }
        finally
        {
            if (!transferred)
            {
                if (continuity is not null)
                {
                    continuity.Dispose();
                }
                else if (delegationCommitment is not null)
                {
                    System.Security.Cryptography.CryptographicOperations.ZeroMemory(
                        delegationCommitment);
                }
                if (continuity is null)
                {
                    foreach (var bridge in bridgeValues)
                    {
                        bridge.Clear();
                    }
                }
            }
        }
    }

    private static void ValidateOrder(IReadOnlyList<ProfileComponent> components)
    {
        if (components.Count < 4 ||
            components[0].Kind != ProfileComponentKind.CanonicalGenesis ||
            components[1].Kind != ProfileComponentKind.GenesisApprovals ||
            components[2].Kind != ProfileComponentKind.SignedDelegation ||
            components.Skip(3).Any(static value =>
                value.Kind != ProfileComponentKind.SignedBridge))
        {
            throw ProfileCarrierErrors.Framing();
        }
    }

    private sealed record VerifiedCarrier(
        ProfileCarrierVerificationResult Result,
        ProfileCarrierContinuity? Continuity);
}
