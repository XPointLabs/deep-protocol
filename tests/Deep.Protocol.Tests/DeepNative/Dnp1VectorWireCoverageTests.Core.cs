using System.Buffers.Binary;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Deep.Protocol.DeepNative;

namespace Deep.Protocol.Tests.DeepNative;

public sealed class VectorWireCoverageTestsCore
{
    [Fact]
    public void GrammarAllExactLengths()
    {
        var tests = new CanonicalGrammarTests();
        tests.MachineRegistry_RecordArithmetic_IsExact();
        tests.RegistryDefinitions_EncodeCanonicalMinimumShapes();
    }

    [Fact]
    public void GrammarTruncatedMaxPlusOne()
    {
        var tests = new CanonicalGrammarTests();
        tests.OuterValidLateVariableLengthMismatch_RejectsBeforeOwnership();
        tests.OuterValidLateLargeDrcInvalidCount_RejectsWithBoundedAllocation();
    }

    [Fact]
    public void GrammarTagOrderDuplicateTrailing()
    {
        var tests = new CanonicalGrammarTests();
        tests.HeaderTagSuiteAndTrailingMutations_Reject(10, 1);
        tests.HeaderTagSuiteAndTrailingMutations_Reject(12, 2);
        tests.HeaderTagSuiteAndTrailingMutations_Reject(14, 1);
    }

    [Fact]
    public void GrammarUnknownSuiteAndPq()
    {
        var tests = new CanonicalGrammarTests();
        tests.HeaderTagSuiteAndTrailingMutations_Reject(6, 0x0101);
    }

    [Fact]
    public void GrammarArtifactDomainCrossType()
    {
        var canonical = Minimum(RecordDefinitions.Dpa1);
        var account = CanonicalGrammar.ComputeReference(ArtifactType.Dpa1, canonical);
        var device = CanonicalGrammar.ComputeReference(ArtifactType.Dpd1, canonical);

        Assert.Equal(account.CanonicalLength, device.CanonicalLength);
        Assert.NotEqual(account.CanonicalHash.ToArray(), device.CanonicalHash.ToArray());
        Assert.NotEqual(CanonicalGrammar.EncodeReference(account),
            CanonicalGrammar.EncodeReference(device));
    }

    [Fact]
    public void GrammarRecordHeaderSuiteCrossFeed()
    {
        var drt = Minimum(RecordDefinitions.Drt1);
        var error = Assert.Throws<RecordException>(() =>
            CanonicalGrammar.Preflight(drt, RecordDefinitions.Dpa1));
        Assert.Equal(RecordError.InvalidLength, error.Error);
    }

    [Fact]
    public void GrammarClosedWireEnums()
    {
        var tests = new CanonicalGrammarTests();
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("DRT1", 2, 0);
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("KRT1", 2, 0);
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("DCP1", 3, 5);
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("DCN1", 26, 2);
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("DPL1", 2, 0);
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("DNR1", 14, 8);
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("DNR1", 15, 32);
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("DPC1", 9, 4);
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("DPR1", 9, 2);
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("DPJ1", 8, 2);
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("DWD1", 10, 14);
        tests.ClosedWireScalarMutation_RejectsBeforeCrypto("RRM1", 7, 14);
    }

    [Fact]
    public void GrammarProtectedHmacFraming() =>
        new CanonicalGrammarTests().ProtectedHmac_IsExactDomainSeparatedAndMutationFails();

    [Fact]
    public void GrammarTranscriptPreimageWidthsAndPrefixes()
    {
        Assert.Equal(168, X25519PossessionVerifier.TranscriptLength);
        Assert.Throws<RecordException>(() => X25519PossessionVerifier.CreateProof(
            new byte[167], new byte[32]));
        Assert.Throws<RecordException>(() => X25519PossessionVerifier.CreateProof(
            new byte[169], new byte[32]));
        Assert.Throws<RecordException>(() => X25519PossessionVerifier.CreateProof(
            new byte[168], new byte[32]));

        var witnessLeaf = Enumerable.Repeat((byte)0x31, 116).ToArray();
        Assert.Equal(CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/witness-log-leaf", witnessLeaf),
            WitnessTreeVerifier.Leaf(witnessLeaf));
        Assert.Throws<RecordException>(() => WitnessTreeVerifier.Leaf(new byte[115]));
        Assert.Throws<RecordException>(() => WitnessTreeVerifier.Leaf(new byte[117]));

        var deployment = Enumerable.Repeat((byte)0x41, 32).ToArray();
        var sequence = U64(7);
        var dcs = Reference(ArtifactType.Dcs1, 0x42);
        var dct = Reference(ArtifactType.Dct1, 0x43);
        var receipts = new[]
        {
            Reference(ArtifactType.Dcn1, 0x44),
            Reference(ArtifactType.Dcn1, 0x45),
            Reference(ArtifactType.Dcn1, 0x46)
        }.SelectMany(static value => value).ToArray();
        var quorumPayload = deployment.Concat(sequence).Concat(dcs).Concat(dct)
            .Concat(receipts).ToArray();
        Assert.Equal(230, quorumPayload.Length);
        Assert.Equal(CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/quorum-digest", quorumPayload),
            GenesisQuorumStateVerifier.ComputeQuorumDigest(
                deployment, sequence, dcs, dct, receipts));
        Assert.Throws<RecordException>(() =>
            GenesisQuorumStateVerifier.ComputeQuorumDigest(
                deployment[..31], sequence, dcs, dct, receipts));
        Assert.Throws<RecordException>(() =>
            GenesisQuorumStateVerifier.ComputeQuorumDigest(
                deployment, sequence[..7], dcs, dct, receipts));
        Assert.Throws<RecordException>(() =>
            GenesisQuorumStateVerifier.ComputeQuorumDigest(
                deployment, sequence, dcs[..37], dct, receipts));
        Assert.Throws<RecordException>(() =>
            GenesisQuorumStateVerifier.ComputeQuorumDigest(
                deployment, sequence, dcs, dct, receipts[..113]));

        var network = Enumerable.Repeat((byte)0x51, 16).ToArray();
        var msm = Reference(ArtifactType.Msm1, 0x52);
        var memberCount = new byte[4];
        var root = Enumerable.Repeat((byte)0x53, 32).ToArray();
        var pma = Reference(ArtifactType.Pma1, 0x54);
        var pmaGeneration = U64(2);
        var pmaEpoch = U64(3);
        var pmr = Reference(ArtifactType.Pmr1, 0x55);
        var pmrGeneration = U64(4);
        var pmrHead = Enumerable.Repeat((byte)0x56, 32).ToArray();
        var pmrSnapshot = Enumerable.Repeat((byte)0x57, 32).ToArray();
        var membershipPayload = network.Concat(msm).Concat(sequence)
            .Concat(memberCount).Concat(root).Concat(pma).Concat(pmaGeneration)
            .Concat(pmaEpoch).Concat(pmr).Concat(pmrGeneration).Concat(pmrHead)
            .Concat(pmrSnapshot).ToArray();
        Assert.Equal(262, membershipPayload.Length);
        Assert.Equal(CanonicalGrammar.Sha256Domain(
            "Deep/NativeRouting/V2/composite-selection", membershipPayload),
            MembershipClosureVerifier.ComputeCompositeSelectionTranscript(
                network, msm, sequence, memberCount, root, pma, pmaGeneration,
                pmaEpoch, pmr, pmrGeneration, pmrHead, pmrSnapshot, []));
        Assert.Throws<RecordException>(() =>
            MembershipClosureVerifier.ComputeCompositeSelectionTranscript(
                network[..15], msm, sequence, memberCount, root, pma, pmaGeneration,
                pmaEpoch, pmr, pmrGeneration, pmrHead, pmrSnapshot, []));
        var oneMember = new byte[] { 0, 0, 0, 1 };
        Assert.Throws<RecordException>(() =>
            MembershipClosureVerifier.ComputeCompositeSelectionTranscript(
                network, msm, sequence, oneMember, root, pma, pmaGeneration,
                pmaEpoch, pmr, pmrGeneration, pmrHead, pmrSnapshot, new byte[145]));
    }

    [Fact]
    public void ApiRelativeAuthorityReflection()
    {
        Type[] authorityTypes =
        [
            typeof(ReleaseRootRelativeFact), typeof(WitnessDelegationRelativeFact),
            typeof(VerifiedIdentityRelative), typeof(CurrentDnrcRelative),
            typeof(CurrentMailboxRoleRelative), typeof(CurrentCutoverRelative)
        ];
        foreach (var type in authorityTypes)
        {
            Assert.Empty(type.GetConstructors(BindingFlags.Public | BindingFlags.Instance));
            Assert.DoesNotContain(type.GetMethods(BindingFlags.Public | BindingFlags.Static),
                method => method.ReturnType == type);
        }
    }

    [Fact]
    public void PackageExactThreeSessionFree()
    {
        var root = FindRepositoryRoot();
        var solution = File.ReadAllText(Path.Combine(root, "Deep.Protocol.slnx"));
        var production = Regex.Matches(solution,
                "Project Path=\"src/([^\"]+)\\.csproj\"", RegexOptions.CultureInvariant)
            .Select(match => match.Groups[1].Value.Replace('\\', '/'))
            .OrderBy(value => value, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(new[]
        {
            "Deep.Protocol.MembershipRoutes/Deep.Protocol.MembershipRoutes",
            "Deep.Protocol.ProfileCarrier/Deep.Protocol.ProfileCarrier",
            "Deep.Protocol/Deep.Protocol"
        }, production);
        Assert.DoesNotContain("Session", solution, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Native", solution, StringComparison.OrdinalIgnoreCase);
    }

    private static byte[] Minimum(RecordDefinition definition)
    {
        var fields = definition.Fields
            .Select(field => (ReadOnlyMemory<byte>)new byte[field.MinimumLength]).ToArray();
        if (definition.Magic == "DPA1") fields[11] = U16(1);
        if (definition.Magic == "DRT1") fields[1] = new byte[] { 1 };
        return CanonicalGrammar.Encode(definition, fields);
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null && !File.Exists(Path.Combine(current.FullName, "Deep.Protocol.slnx")))
            current = current.Parent;
        return current?.FullName ?? throw new InvalidOperationException("Repository root not found.");
    }

    private static byte[] U16(ushort value)
    {
        var bytes = new byte[2];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] Reference(ArtifactType type, byte value) =>
        CanonicalGrammar.EncodeReference(new ArtifactReference(
            type, 1, Enumerable.Repeat(value, 32).ToArray()));
}
