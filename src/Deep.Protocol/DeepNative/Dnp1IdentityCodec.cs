namespace Deep.Protocol.DeepNative;

public static class IdentityCodec
{
    public static AccountCertificate DecodeAccountCertificate(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dpa1));

    public static DeviceCertificate DecodeDeviceCertificate(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dpd1));

    public static MailboxRoleCertificate DecodeMailboxRoleCertificate(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dpm1));

    public static RevocationSnapshot DecodeRevocationSnapshot(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Drs1));

    public static RevocationTarget DecodeRevocationTarget(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Drt1));

    public static KeyRotation DecodeKeyRotation(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Krt1));

    public static KeyRevocation DecodeKeyRevocation(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Krf1));
}
