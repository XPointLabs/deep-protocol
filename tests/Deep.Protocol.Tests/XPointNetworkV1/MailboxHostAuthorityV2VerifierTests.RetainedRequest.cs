using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;
using Deep.Protocol.XPointNetworkV1;
using Sodium;
using Fixture = Deep.Protocol.Tests.XPointNetworkV1.XPointOnionCapabilityProducerTests.Fixture;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class MailboxHostAuthorityV2VerifierTests
{
    [Theory]
    [InlineData(false, false)]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task RetainedRequest_UsesCurrentTimeAndActualSignedHistoryNotOldProjectionTime(
        bool cold, bool unchangedEpoch)
    {
        var fixture = Fixture.Create();
        var input = await fixture.VerifyMailboxHistoryAsync(cold, unchangedEpoch);
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        var old = input.Network.Closure!.RetainedPmts[0];
        Assert.Equal(210UL, BinaryPrimitives.ReadUInt64BigEndian(old.Field(12).Span));
        var exact = RetainedRequest(input.Network, old);
        var request = await host.VerifyRetainedReadRequestAsync(exact);
        var window = await request.ReadCurrentTimeAsync();
        Assert.Equal(220UL, window.LowerUnixSeconds);
        Assert.Equal(230UL, window.UpperUnixSeconds);
        Assert.Equal(ContactCodec.ArtifactReference(ProtocolMagic.PMT2, old).CanonicalBytes.ToArray(),
            request.ProjectionReference.ToArray());
        Assert.Equal(exact, request.ExactXmg1.ToArray());
        Assert.Equal(Bytes(32, 0x96), request.SelectionHash.ToArray());
        await request.EnsureCurrentAsync();
        // The arbitrary PMS hash/capability in this request is deliberately not
        // a verified route or ownership claim. No grant is constructed here.
    }

    [Theory]
    [InlineData("deposit")]
    [InlineData("network")]
    [InlineData("projection")]
    [InlineData("signature")]
    public async Task RetainedRequest_RejectsInvalidScopeBeforeClockOrAnyLookup(string defect)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        var exact = RetainedRequest(input.Network, input.Network.Closure!.RetainedPmts[0], defect);
        if (defect == "signature") exact[^1] ^= 1;
        var before = clock.Reads;
        if (defect == "signature")
        {
            var error = await Assert.ThrowsAsync<ContactFormatException>(() => host.VerifyRetainedReadRequestAsync(exact).AsTask());
            Assert.Equal(ContactValidationStage.Signature, error.Stage);
            Assert.Equal("MailboxGrantHolderSignatureVerificationFailed", error.Code);
        }
        else
            await Assert.ThrowsAsync<CryptographicException>(() => host.VerifyRetainedReadRequestAsync(exact).AsTask());
        Assert.Equal(before, clock.Reads);
    }

    [Theory]
    [InlineData("expired")]
    [InlineData("future")]
    [InlineData("too-long")]
    [InlineData("host-bound")]
    public async Task RetainedRequest_RejectsSignedWindowOutsideFullCurrentBounds(string defect)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        var exact = RetainedRequest(input.Network, input.Network.Closure!.RetainedPmts[0], defect);
        await Assert.ThrowsAsync<CryptographicException>(() => host.VerifyRetainedReadRequestAsync(exact).AsTask());
    }

    [Fact]
    public async Task RetainedRequest_CannotManufactureMissingHistoryUsingAValidHolderProof()
    {
        var fixture = Fixture.Create(); var history = await fixture.VerifyMailboxHistoryAsync();
        var omitted = await fixture.VerifyMailboxAsync();
        var host = await Verify(fixture, omitted, new Clock());
        await Assert.ThrowsAsync<CryptographicException>(() => host.VerifyRetainedReadRequestAsync(
            RetainedRequest(history.Network, history.Network.Closure!.RetainedPmts[0])).AsTask());
    }

    [Fact]
    public async Task RetainedRequest_CapturesInputBeforeCallbacksAndReturnsOnlyDefensiveCopies()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        var exact = RetainedRequest(input.Network, input.Network.Closure!.RetainedPmts[0]);
        var original = exact.ToArray();
        clock.OnRead = () => Array.Fill(exact, (byte)0);
        var request = await host.VerifyRetainedReadRequestAsync(exact);
        foreach (var copy in new[] { request.ExactXmg1, request.ProjectionReference, request.SelectionHash })
        { Assert.True(MemoryMarshal.TryGetArray(copy, out var segment)); segment.Array!.AsSpan(segment.Offset, segment.Count).Clear(); }
        Assert.Equal(original, request.ExactXmg1.ToArray());
        Assert.Equal(ContactCodec.Decode(ProtocolMagic.XMG1, original).Field(7).ToArray(), request.ProjectionReference.ToArray());
        Assert.Equal(Bytes(32, 0x96), request.SelectionHash.ToArray());
    }

    [Theory]
    [InlineData(false, "expiry")]
    [InlineData(false, "rollback")]
    [InlineData(false, "boot")]
    [InlineData(false, "cancel")]
    [InlineData(true, "expiry")]
    [InlineData(true, "rollback")]
    [InlineData(true, "boot")]
    [InlineData(true, "cancel")]
    public async Task RetainedRequest_RechecksBeforeMintingOrReturningTime(bool mint, string defect)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        var exact = RetainedRequest(input.Network, input.Network.Closure!.RetainedPmts[0]);
        var request = mint ? null : await host.VerifyRetainedReadRequestAsync(exact);
        using var cancellation = new CancellationTokenSource(); var reads = 0;
        clock.OnRead = () =>
        {
            if (++reads != 2) return;
            if (defect == "expiry") clock.Sample = 1_045; // upper250 equals request expiry, before host expiry.
            if (defect == "rollback") clock.Sample = 1_024;
            if (defect == "boot") clock.Boot = Bytes(16, 0xff);
            if (defect == "cancel") cancellation.Cancel();
        };
        Task task = mint ? host.VerifyRetainedReadRequestAsync(exact, cancellation.Token).AsTask() :
            request!.ReadCurrentTimeAsync(cancellation.Token).AsTask();
        if (defect == "cancel") await Assert.ThrowsAnyAsync<OperationCanceledException>(() => task);
        else await Assert.ThrowsAsync<CryptographicException>(() => task);
    }

    [Theory]
    [InlineData(4)]
    [InlineData(6)]
    [InlineData(10)]
    public async Task RetainedRequest_UnknownVersionSuiteOrReservedByteRejectsBeforeClock(int offset)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        var exact = RetainedRequest(input.Network, input.Network.Closure!.RetainedPmts[0]);
        exact[offset] ^= 0xff; var before = clock.Reads;
        await Assert.ThrowsAsync<ContactFormatException>(() => host.VerifyRetainedReadRequestAsync(exact).AsTask());
        Assert.Equal(before, clock.Reads);
    }

    [Fact]
    public async Task RetainedRequest_ExactMaximumWindowIsAcceptedWithoutExtendingIt()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        var exact = RetainedRequest(input.Network, input.Network.Closure!.RetainedPmts[0], "maximum-window");
        var request = await host.VerifyRetainedReadRequestAsync(exact);
        Assert.Equal(exact, request.ExactXmg1.ToArray());
    }

    [Theory]
    [InlineData(0)]
    [InlineData(434)]
    [InlineData(436)]
    public async Task RetainedRequest_HostileLengthAndPreCancellationRejectBeforeClock(int length)
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        var before = clock.Reads;
        await Assert.ThrowsAsync<CryptographicException>(() => host.VerifyRetainedReadRequestAsync(new byte[length]).AsTask());
        using var cancellation = new CancellationTokenSource(); cancellation.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => host.VerifyRetainedReadRequestAsync(
            RetainedRequest(input.Network, input.Network.Closure!.RetainedPmts[0]), cancellation.Token).AsTask());
        Assert.Equal(before, clock.Reads);
    }

    [Fact]
    public async Task RetainedRequest_UsesOriginalWindowOnLaterCallsAndExactBoundary()
    {
        var fixture = Fixture.Create(); var input = await fixture.VerifyMailboxHistoryAsync();
        var clock = new Clock { Sample = 1_025 }; var host = await Verify(fixture, input, clock);
        var request = await host.VerifyRetainedReadRequestAsync(
            RetainedRequest(input.Network, input.Network.Closure!.RetainedPmts[0]));
        clock.Sample = 1_044;
        Assert.Equal(249UL, (await request.ReadCurrentTimeAsync()).UpperUnixSeconds);
        clock.Sample = 1_045;
        await Assert.ThrowsAsync<CryptographicException>(() => request.EnsureCurrentAsync().AsTask());
        clock.Sample = 1_046;
        await Assert.ThrowsAsync<CryptographicException>(() => request.EnsureCurrentAsync().AsTask());
        Assert.Equal(250UL, BinaryPrimitives.ReadUInt64BigEndian(
            ContactCodec.Decode(ProtocolMagic.XMG1, request.ExactXmg1.Span).Field(10).Span));
    }

    [Fact]
    public void RetainedRequest_ActualPublicApiHasNoConstructionClockOrHistoricalFlagBypass()
    {
        Assert.Empty(typeof(VerifiedMailboxRetainedReadRequestV2).GetConstructors());
        var method = typeof(VerifiedMailboxHostAuthorityV2).GetMethod(nameof(VerifiedMailboxHostAuthorityV2.VerifyRetainedReadRequestAsync))!;
        Assert.Equal(typeof(ValueTask<VerifiedMailboxRetainedReadRequestV2>), method.ReturnType);
        Assert.Equal([typeof(ReadOnlyMemory<byte>), typeof(CancellationToken)],
            method.GetParameters().Select(parameter => parameter.ParameterType));
        Assert.All(typeof(VerifiedMailboxRetainedReadRequestV2).GetProperties(), property => Assert.False(property.CanWrite));
        Assert.Equal(typeof(ValueTask<DeepIdV2ContactRouteTimeWindow>),
            typeof(VerifiedMailboxRetainedReadRequestV2).GetMethod(nameof(VerifiedMailboxRetainedReadRequestV2.ReadCurrentTimeAsync))!.ReturnType);
        Assert.Equal(typeof(VerifiedMailboxHostAuthorityV2).Assembly, typeof(VerifiedMailboxRetainedReadRequestV2).Assembly);
    }

    private static byte[] RetainedRequest(VerifiedOnionNetworkContext network, ContactRecord projection,
        string defect = "")
    {
        var key = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x91));
        var start = defect == "future" ? 221UL : defect == "too-long" ? 100UL :
            defect == "maximum-window" ? 130UL : 215UL;
        var end = defect == "expired" ? 230UL : defect == "host-bound" ? 310UL : 250UL;
        ReadOnlyMemory<byte>[] fields = [defect == "network" ? Bytes(16, 0xff) : network.NetworkId,
            Bytes(32, 0x92), Bytes(32, 0x94), Bytes(32, 0x95), key.PublicKey,
            new byte[] { defect == "deposit" ? (byte)MailboxCapabilityDomain.Deposit : (byte)MailboxCapabilityDomain.Retrieve },
            defect == "projection" ? new ContactArtifactReference(ProtocolMagic.PMT2, 1, Bytes(32, 0xff)).CanonicalBytes :
                ContactCodec.ArtifactReference(ProtocolMagic.PMT2, projection).CanonicalBytes,
            Bytes(32, 0x96), U64Request(start), U64Request(end), Bytes(32, 0x97), Bytes(64, 0x98)];
        var unsigned = ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XMG1, fields);
        fields[11] = PublicKeyAuth.SignDetached(unsigned.SignatureInput.ToArray(), key.PrivateKey);
        return ContactCodec.AuthorForOperationalAuthority(ProtocolMagic.XMG1, fields).CanonicalBytes.ToArray();
    }

    private static byte[] U64Request(ulong value)
    { var result = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(result, value); return result; }
}
