using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.Identity;

namespace Deep.Protocol.Tests.Identity;

public sealed class DeepPermanentIdV1Tests
{
    private const string Expected = "deep1qxdaxajwwzsqeer8aer3me4ugf7cp0tg00zghca6gsgwp4wz46r26m5vazstw5v9nug455ny65c4e2qsc99up";
    private const string Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    [Fact]
    public void FromCapabilities_MatchesIndependentRfc8032AndBip350Vector()
    {
        using var phrase = VerifyMnemonic();
        using var capabilities = DeepRecoveryV1.DeriveAccountCapabilities(
            phrase,
            Convert.FromHexString("000102030405060708090a0b0c0d0e0f"),
            1);

        var deepId = DeepPermanentIdV1.FromCapabilities(capabilities);

        Assert.Equal(Expected, deepId.CanonicalText);
        Assert.Equal(DeepPermanentIdV1.CanonicalTextLength, deepId.CanonicalText.Length);
        Assert.Equal("019bd3764e70a00ce467ee471de6bc427d80bd687bc48be3ba4410e0d5c2ae86ad6e8ce8a0b751859f115a5264d5315ca8", Convert.ToHexStringLower(deepId.Payload.Span));
    }

    private static VerifiedDeepRecoveryPhrase VerifyMnemonic()
    {
        var utf8 = Encoding.ASCII.GetBytes(Mnemonic);
        try
        {
            return DeepRecoveryV1.VerifyCanonicalUtf8(utf8);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8);
        }
    }

    [Fact]
    public void ParseCanonical_RoundTripsAndReturnsDefensiveCopies()
    {
        var parsed = DeepPermanentIdV1.ParseCanonical(Expected);
        var publicKey = parsed.AddressPublicKey.ToArray();
        var capability = parsed.ResolverReadCapability.ToArray();
        publicKey[0] ^= 0xff;
        capability[0] ^= 0xff;

        Assert.Equal(Expected, parsed.CanonicalText);
        Assert.Equal("9bd3764e70a00ce467ee471de6bc427d80bd687bc48be3ba4410e0d5c2ae86ad", Convert.ToHexStringLower(parsed.AddressPublicKey.Span));
        Assert.Equal("6e8ce8a0b751859f115a5264d5315ca8", Convert.ToHexStringLower(parsed.ResolverReadCapability.Span));
        Assert.NotEqual(publicKey, parsed.AddressPublicKey.ToArray());
        Assert.NotEqual(capability, parsed.ResolverReadCapability.ToArray());
    }

    [Theory]
    [InlineData("DEEP1QXDAXAJWWZSQEER8AER3ME4UGF7CP0TG00ZGHCA6GSGWP4WZ46R26M5VAZSTW5V9NUG455NY65C4E2QSC99UP")]
    [InlineData("deep1qxdaxajwwzsqeer8aer3me4ugf7cp0tg00zghca6gsgwp4wz46r26m5vazstw5v9nug455ny65c4e2qsc99uq")]
    [InlineData("deep1qxdaxajwwzsqeer8aer3me4ugf7cp0tg00zghca6gsgwp4wz46r26m5vazstw5v9nug455ny65c4e2qsc99u")]
    [InlineData("xdeep1qxdaxajwwzsqeer8aer3me4ugf7cp0tg00zghca6gsgwp4wz46r26m5vazstw5v9nug455ny65c4e2qsc99up")]
    public void ParseCanonical_RejectsNonCanonicalOrCorruptedText(string value)
    {
        Assert.Throws<ArgumentException>(() => DeepPermanentIdV1.ParseCanonical(value));
    }

    [Fact]
    public void Create_RejectsWrongComponentLengths()
    {
        Assert.Throws<ArgumentException>(() => DeepPermanentIdV1.Create(new byte[31], new byte[16]));
        Assert.Throws<ArgumentException>(() => DeepPermanentIdV1.Create(new byte[32], new byte[15]));
    }
}
