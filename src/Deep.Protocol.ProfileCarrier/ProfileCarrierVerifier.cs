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
            return new ProfileCarrierVerificationResult(
                recomposed.FilePayloadSha256.Span,
                recomposed.Fingerprint,
                recomposed.MinimumProtocol,
                recomposed.MaximumProtocol,
                recomposed.ComponentCount,
                recomposed.BridgeCount);
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
}
