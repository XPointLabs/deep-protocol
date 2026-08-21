namespace Deep.Protocol.DeepNative;

/// <summary>Carry-only decoders. Decoding does not authenticate local protected state.</summary>
public static class ProtectedStateCodec
{
    public static ProtectedLocalPin DecodeLocalPin(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dpl1));

    public static ProtectedBootstrapGuard DecodeBootstrapGuard(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dbg1));

    public static RegistryIdentityBinding DecodeRegistryIdentityBinding(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Rib1));

    public static XNodeIdentityBinding DecodeXNodeIdentityBinding(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Xib1));

    public static WitnessLastKnownGood DecodeWitnessLastKnownGood(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dwl1));

    public static MembershipRoutingLastKnownGood DecodeMembershipRoutingLastKnownGood(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Mrlc));

    public static OuterPeerJournalRecord DecodeOuterPeerJournal(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dpj1));

    public static ReleaseRootLastKnownGood DecodeReleaseRootLastKnownGood(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Rrl1));
}
