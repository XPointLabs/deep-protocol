using System.Security.Cryptography;
using Deep.Protocol.ContactV1;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.XPointNetworkV1;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed partial class MailboxRetainedReadIssuanceV2Tests
{
    [Fact]
    public async Task OriginalRetrieve_AuthenticatesExpiredSignedFactsWithoutCreatingCurrentAuthority()
    {
        var f = await State.Create();
        var exact = await ShortOriginalGrant(f);
        var policy = f.Host.RetainedReadPolicyBytes;
        await f.Host.RequireOriginalRetainedReadGrantAsync(policy, f.Route.ExactBytes, f.Request, exact);
        f.Clock.Sample = 1_045; // lower240/upper250; original grant ends240.
        await Assert.ThrowsAsync<CryptographicException>(() => f.Host.VerifyRetainedReadSuccessAsync(
            f.Route.ExactBytes, f.Request, exact).AsTask());
        await f.Host.RequireOriginalRetainedReadGrantAsync(policy, f.Route.ExactBytes, f.Request, exact);
        var method = typeof(VerifiedMailboxHostAuthorityV2).GetMethod(nameof(VerifiedMailboxHostAuthorityV2.RequireOriginalRetainedReadGrantAsync))!;
        Assert.Equal(typeof(ValueTask), method.ReturnType);
        Assert.Equal(new[] { typeof(ReadOnlyMemory<byte>), typeof(ReadOnlyMemory<byte>), typeof(ReadOnlyMemory<byte>),
            typeof(ReadOnlyMemory<byte>), typeof(CancellationToken) }, method.GetParameters().Select(parameter => parameter.ParameterType));
    }

    [Theory]
    [InlineData("policy")]
    [InlineData("request")]
    [InlineData("result")]
    [InlineData("role")]
    public async Task OriginalRetrieve_RejectsChangedSigningEvidenceOrRole(string defect)
    {
        var f = await State.Create(); var exact = await ShortOriginalGrant(f);
        var policy = f.Host.RetainedReadPolicyBytes.ToArray(); var request = f.Request.ToArray();
        if (defect == "policy") policy[^1] ^= 1;
        if (defect == "request") request[^1] ^= 1;
        if (defect == "result") exact[^1] ^= 1;
        if (defect == "role") request = f.AuthorRequest(MailboxCapabilityDomain.Deposit);
        var error = await Record.ExceptionAsync(() => f.Host.RequireOriginalRetainedReadGrantAsync(
            policy, f.Route.ExactBytes, request, exact).AsTask());
        Assert.True(error is CryptographicException or ContactFormatException or MailboxAuthenticatedCapabilityException);
    }

    [Fact]
    public async Task OriginalRetrieve_CapturesBeforeCallbacksAndRejectsHostileLengthOrCancellation()
    {
        var f = await State.Create(); var response = await ShortOriginalGrant(f);
        var policy = f.Host.RetainedReadPolicyBytes.ToArray(); var request = f.Request.ToArray(); var route = f.Route.ExactBytes.ToArray();
        f.Clock.OnRead = () => { Array.Clear(policy); Array.Clear(request); Array.Clear(route); Array.Clear(response); };
        await f.Host.RequireOriginalRetainedReadGrantAsync(policy, route, request, response);
        var reads = 0; f.Clock.OnRead = () => reads++;
        using var cancelled = new CancellationTokenSource(); cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => f.Host.RequireOriginalRetainedReadGrantAsync(
            f.Host.RetainedReadPolicyBytes, f.Route.ExactBytes, f.Request, new byte[510], cancelled.Token).AsTask());
        await Assert.ThrowsAsync<CryptographicException>(() => f.Host.RequireOriginalRetainedReadGrantAsync(
            f.Host.RetainedReadPolicyBytes, f.Route.ExactBytes, new byte[434], new byte[510]).AsTask());
        Assert.Equal(0, reads);
    }

    private static async Task<byte[]> ShortOriginalGrant(State f)
    {
        var original = await (await f.Issuance()).AuthorSuccessAsync(new Issuer());
        var grant = MailboxAuthenticatedCapabilityCodec.DecodeGrant(ContactCodec.Decode("XMC2", original.Span).Field(8).Span);
        grant = new SodiumMailboxCapabilityCrypto().SignGrant(grant with { ExpiresAtUnixSeconds = 240 }, B(32, 0xe2));
        return MailboxGrantResultAuthor.AuthorSuccess(ContactCodec.Decode("XMG2", f.Request),
            f.Route.ExactBytes.Span, grant, 230, 250).CanonicalBytes.ToArray();
    }
}
