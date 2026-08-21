namespace Deep.Protocol.DeepNative;

public static class CutoverCodec
{
    public static ReleaseRootManifest DecodeReleaseRootManifest(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Rrm1));

    public static CutoverManifest DecodeManifest(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dcm1));

    public static AccountResetAuthorization DecodeAccountReset(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dra1));

    public static WitnessDelegation DecodeWitnessDelegation(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dwd1));

    public static ComponentCheckpoint DecodeComponentCheckpoint(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dcp1));

    public static DeploymentSet DecodeDeploymentSet(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dcs1));

    public static CasTranscript DecodeCasTranscript(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dct1));

    public static WitnessReceipt DecodeWitnessReceipt(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dcn1));

    public static QuorumReceipt DecodeQuorumReceipt(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dcq1));

    public static HeadLease DecodeHeadLease(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dhl1));

    public static QuorumLease DecodeQuorumLease(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dcl1));

    public static WitnessTermination DecodeWitnessTermination(ReadOnlySpan<byte> canonical) =>
        new(CanonicalGrammar.DecodeOwned(canonical, RecordDefinitions.Dwt1));
}
