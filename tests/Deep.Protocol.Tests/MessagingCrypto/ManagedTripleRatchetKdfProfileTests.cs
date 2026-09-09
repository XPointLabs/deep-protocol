using Deep.Protocol.MessagingCrypto;

namespace Deep.Protocol.Tests.MessagingCrypto;

public sealed class ManagedTripleRatchetKdfProfileTests
{
    [Fact]
    public void FrozenProfile_MatchesIndependentDoubleAndSpqrVectors()
    {
        using var ecRoot = ManagedTripleRatchetKdfProfile.DeriveEcRoot(
            Fill(0x11), Fill(0x22));
        Assert.Equal(
            "3E4085A1522F7CE706CA63F0F1F39A54F499DA18BF84C11EE4B351A2642A74CC",
            Hex(ecRoot.UseRoot(static value => value.ToArray())));
        Assert.Equal(
            "66084BCFA455A02A6AB19EF2D3CE1E9D077EA66913440163EB52DE0F241A29CC",
            Hex(ecRoot.UseChain(static value => value.ToArray())));

        using var ecChain = ManagedTripleRatchetKdfProfile.DeriveEcChain(Fill(0x33));
        Assert.Equal(
            "E256B7764ADC4E292A581F576F636476856DA3EBE05F5C3F31E1A17DDDD164B2",
            Hex(ecChain.UseNextChain(static value => value.ToArray())));
        Assert.Equal(
            "33DF155471A76DD8FABD213B3D46F7B16A786298411A3F5F0F376D7F473FB0F2",
            Hex(ecChain.UseMessageKey(static value => value.ToArray())));

        using var initial = ManagedTripleRatchetKdfProfile.InitializeSpqr(Fill(0x44));
        Assert.Equal(
            "BFA481BC111C4E18EE201EB645413F81AFAA93F16164723D1CEBF52850A05250",
            Hex(initial.UseRoot(static value => value.ToArray())));
        Assert.Equal(
            "B7DF4FD88681305743E6E93F5E40A495E06AE0A60E26E5C6ED9CD643511A3FC3",
            Hex(initial.UseAliceToBob(static value => value.ToArray())));
        Assert.Equal(
            "0A57862BA65B02CFEBB4B0E90D3565A068CB7C3C9D65CA4B8566A6C77CD1D4D7",
            Hex(initial.UseBobToAlice(static value => value.ToArray())));

        using var epoch = ManagedTripleRatchetKdfProfile.AdvanceSpqrEpoch(
            Fill(0x55), Fill(0x66), 7);
        Assert.Equal(
            "0028CFE64BE550C0C9A2F621E37B2260D6A1FBED7543A982E927073F668437E8",
            Hex(epoch.UseRoot(static value => value.ToArray())));
        Assert.Equal(
            "6EB16626603AE9D035EB1A55F4D335BD86121EB38710504D539169408663A0D7",
            Hex(epoch.UseAliceToBob(static value => value.ToArray())));
        Assert.Equal(
            "1E7EF9121D4603C0D76F84CF934D3B339A49BF9391B8BB632217E7F72A423C40",
            Hex(epoch.UseBobToAlice(static value => value.ToArray())));

        using var chain = ManagedTripleRatchetKdfProfile.DeriveSpqrChain(
            Fill(0x77), 7, TripleRatchetDirection.AliceToBob, 9);
        Assert.Equal(
            "C28BC8D96B8F664E5C285524852F3467EBE3C44B15C3AB6B4923588174838FE3",
            Hex(chain.UseNextChain(static value => value.ToArray())));
        Assert.Equal(
            "295AB2823B1D8BDC6B3446C5F7430C7906C1DFABDE62C629A80256EBB6517A96",
            Hex(chain.UseMessageKey(static value => value.ToArray())));
    }

    [Fact]
    public void DirectionAndCounter_AreBoundAndOwnedOutputsFailAfterDispose()
    {
        var alice = ManagedTripleRatchetKdfProfile.DeriveSpqrChain(
            Fill(0x77), 7, TripleRatchetDirection.AliceToBob, 9);
        using var bob = ManagedTripleRatchetKdfProfile.DeriveSpqrChain(
            Fill(0x77), 7, TripleRatchetDirection.BobToAlice, 9);
        using var nextCounter = ManagedTripleRatchetKdfProfile.DeriveSpqrChain(
            Fill(0x77), 7, TripleRatchetDirection.AliceToBob, 10);
        var aliceMessage = alice.UseMessageKey(static value => value.ToArray());
        Assert.NotEqual(
            aliceMessage,
            bob.UseMessageKey(static value => value.ToArray()));
        Assert.NotEqual(
            aliceMessage,
            nextCounter.UseMessageKey(static value => value.ToArray()));

        alice.Dispose();
        Assert.Throws<ObjectDisposedException>(() =>
            alice.UseMessageKey(static value => value.ToArray()));
    }

    [Fact]
    public void InvalidSecretsEpochAndDirection_RejectBeforeDerivation()
    {
        var zero = new byte[32];
        Assert.Throws<MessagingCryptoException>(() =>
            ManagedTripleRatchetKdfProfile.DeriveEcRoot(zero, Fill(0x22)));
        Assert.Throws<MessagingCryptoException>(() =>
            ManagedTripleRatchetKdfProfile.DeriveEcRoot(Fill(0x11), zero));
        Assert.Throws<MessagingCryptoException>(() =>
            ManagedTripleRatchetKdfProfile.InitializeSpqr(zero));
        Assert.Throws<MessagingCryptoException>(() =>
            ManagedTripleRatchetKdfProfile.AdvanceSpqrEpoch(Fill(0x11), Fill(0x22), 0));
        Assert.Throws<MessagingCryptoException>(() =>
            ManagedTripleRatchetKdfProfile.DeriveSpqrChain(
                Fill(0x11), 0, (TripleRatchetDirection)3, 0));
    }

    private static byte[] Fill(byte value) => Enumerable.Repeat(value, 32).ToArray();
    private static string Hex(byte[] value) => Convert.ToHexString(value);
}
