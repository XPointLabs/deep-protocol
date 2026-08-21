using System.Buffers.Binary;
using System.Reflection;

namespace Deep.Protocol.DeepNative;

public sealed class GenesisAuthorReplayStateTests
{
    [Theory]
    [InlineData(0, typeof(GenesisCreatedReplayState))]
    [InlineData(1, typeof(GenesisExternalCommittedReplayState))]
    [InlineData(2, typeof(GenesisCompletedReplayState))]
    public void AuthenticatedJournal_MapsToOneClosedStateWithoutRawPhase(
        byte phase,
        Type expectedType)
    {
        var state = RecoveryVerifier.InspectGenesisAuthorReplayState(
            new GenesisAuthorJournalSnapshot(Journal(phase)));

        Assert.IsType(expectedType, state);
        Assert.True(state.NoAuthorityClaim);
        Assert.DoesNotContain(state.GetType().GetProperties(BindingFlags.Public |
            BindingFlags.Instance), property =>
            property.Name.Contains("Phase", StringComparison.OrdinalIgnoreCase));
        Assert.Empty(state.GetType().GetConstructors(BindingFlags.Public |
            BindingFlags.Instance));
    }

    [Fact]
    public void LocalCommitted_ReturnsOnlyFreshNormalRestoreRequirement()
    {
        var state = Assert.IsType<GenesisCompletedReplayState>(
            RecoveryVerifier.InspectGenesisAuthorReplayState(
                new GenesisAuthorJournalSnapshot(Journal(2))));

        Assert.True(state.RequiresFreshNormalCurrentRestore);
        Assert.DoesNotContain(state.GetType().GetProperties(BindingFlags.Public |
            BindingFlags.Instance), property =>
            property.PropertyType == typeof(RecoveryCandidatePlan) ||
            property.PropertyType == typeof(RecoveryMaterializationPlan));
    }

    private static byte[] Journal(byte phase)
    {
        var value = new byte[GenesisProtectedRecords.GajLength];
        "GAJ1"u8.CopyTo(value); value[4] = 1;
        value.AsSpan(8, 16).Fill(1);
        value.AsSpan(24, 32).Fill(2);
        BinaryPrimitives.WriteUInt16BigEndian(value.AsSpan(56, 2), 1);
        value.AsSpan(58, 32).Fill(3);
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(90, 8), 1);
        value.AsSpan(98, 32).Fill(4);
        value.AsSpan(130, 32).Fill(5);
        value.AsSpan(162, 32).Fill(6);
        value[194] = phase;
        value.AsSpan(195, 32).Fill(7);
        value.AsSpan(227, 38).Fill(8);
        for (var index = 0; index < 4; index++)
            value.AsSpan(265 + index * 38, 38).Fill(checked((byte)(9 + index)));
        value.AsSpan(417, 38).Fill(13);
        value.AsSpan(455, 38).Fill(14);
        value.AsSpan(493, 32).Fill(15);
        value.AsSpan(525, 32).Fill(16);
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(557, 8), 1);
        value.AsSpan(775, 32).Fill(17);
        BinaryPrimitives.WriteUInt64BigEndian(value.AsSpan(807, 8), checked((ulong)phase + 1));
        value.AsSpan(816, 32).Fill(18);
        value.AsSpan(848, 32).Fill(19);
        if (phase > 0)
        {
            value.AsSpan(565, 32).Fill(20);
            value.AsSpan(597, 38).Fill(21);
            value.AsSpan(635, 38).Fill(22);
            value.AsSpan(673, 32).Fill(23);
        }
        if (phase == 2)
        {
            value.AsSpan(635, 38).CopyTo(value.AsSpan(705, 38));
            value.AsSpan(673, 32).CopyTo(value.AsSpan(743, 32));
        }
        return value;
    }
}
