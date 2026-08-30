using Deep.Protocol.Registry;

namespace Deep.Protocol.DeepNative;

internal static class ArtifactRegistry
{
    internal const ushort IdentityAuthV1Ed25519 =
        DeepProtocolIdentifiers.Suites.IdentityAuthV1Ed25519;
    internal const ushort CommittedUnsigned =
        DeepProtocolIdentifiers.Suites.DnpUnsignedCommittedV1;
    internal const ushort ProtectedHmacSha256 =
        DeepProtocolIdentifiers.Suites.ProtectedStateHmacSha256V1;
    internal const ushort ProtectedAead =
        DeepProtocolIdentifiers.Suites.ProtectedStateAeadV1;

    internal static bool IsKnown(ArtifactType type) =>
        DeepProtocolRegistryGenerated.IsKnownDnp1ArtifactType((ushort)type);

    internal static bool IsRetained(ArtifactType type) =>
        DeepProtocolRegistryGenerated.IsRetainedDnp1ArtifactType((ushort)type);

    internal static string GetNewArtifactDomain(ArtifactType type) =>
        DeepProtocolRegistryGenerated.GetDnp1ArtifactHashDomain((ushort)type)
            ?? throw new RecordException(
                RecordError.InvalidArtifactReference,
                "The artifact type does not use a Wave 1 artifact domain.");

    internal static string GetProtectedDomain(string magic) =>
        DeepProtocolRegistryGenerated.GetDnp1ProtectedDomain(magic)
            ?? throw new RecordException(
                RecordError.InvalidField,
                "The record does not use the protected-state HMAC construction.");
}
