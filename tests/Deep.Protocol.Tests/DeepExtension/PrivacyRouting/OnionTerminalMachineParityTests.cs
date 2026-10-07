using System.Text.Json;
using ProtocolMagic = Deep.Protocol.Registry.DeepProtocolIdentifiers.Magic;
using Deep.Protocol.ContactV2;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.PrivacyRouting;

namespace Deep.Protocol.Tests.DeepExtension.PrivacyRouting;

/// <summary>Machine metadata versus actual current endpoint/codec contracts.
/// This neither mints authenticated authority nor qualifies a node/device.</summary>
public sealed class OnionTerminalMachineParityTests
{
    [Theory]
    [InlineData(1, "Store")]
    [InlineData(2, "Retrieve")]
    [InlineData(3, "Acknowledge")]
    [InlineData(4, "ContactResolve")]
    [InlineData(5, "GroupControl")]
    public void FrozenTerminalMetadataMatchesCurrentContracts(int id, string name)
    {
        using var manifest = JsonDocument.Parse(File.ReadAllText(FindVectors()));
        var operations = manifest.RootElement.GetProperty("terminalOperations");
        Assert.Equal(5, operations.GetArrayLength());
        var row = operations[id - 1];
        Assert.Equal(id, row.GetProperty("id").GetInt32());
        Assert.Equal(name, row.GetProperty("name").GetString());
        Assert.Equal(name, ((PrivacyRoutingOperation)id).ToString());
        string[] requests, results;
        int requestMaximum, resultMaximum;
        if (id <= 3)
        {
            var endpoint = id switch
            {
                1 => MailboxWireHttpContract.Store,
                2 => MailboxWireHttpContract.Retrieve,
                _ => MailboxWireHttpContract.Acknowledge,
            };
            Assert.Equal(MailboxWireFrame.Mau3, endpoint.RequestFrame);
            requests = [ProtocolMagic.MAU3];
            results = [id switch { 1 => ProtocolMagic.MQR3, 2 => ProtocolMagic.MRP1, _ => ProtocolMagic.MAR1 }];
            requestMaximum = endpoint.MaximumRequestBytes;
            // XPR1's 20-byte header shares the bounded application payload.
            resultMaximum = Math.Min(endpoint.MaximumResponseBytes,
                PrivacyRoutingLimits.MaximumTerminalSuccessBodyBytes);
        }
        else if (id == 4)
        {
            requests = [ProtocolMagic.XPU1, ProtocolMagic.XIQ1, ProtocolMagic.XPK1,
                ProtocolMagic.XUW1, ProtocolMagic.XUQ1, ProtocolMagic.XMG2,
                ProtocolMagic.XPP1, ProtocolMagic.XCA2];
            results = [ProtocolMagic.XPO1, ProtocolMagic.XIS1, ProtocolMagic.XPC1,
                ProtocolMagic.XUS1, ProtocolMagic.XMC2, ProtocolMagic.XIC1, ProtocolMagic.XCS2];
            requestMaximum = ContactCoordinationOnionCodec.MaximumRequestBytes;
            Assert.Equal(12 + 171_614, requestMaximum); // DR-0089 key-free one-time publication envelope
            Assert.Equal(PrivacyRoutingLimits.MaximumContactResolverRequestBytes, requestMaximum);
            Assert.Equal(OnionLimits.MaximumContactResolverRequestBytes, requestMaximum);
            resultMaximum = PrivacyRoutingLimits.MaximumContactResolverResponseBytes;
            Assert.Equal(OnionLimits.MaximumContactResolverResponseBytes, resultMaximum);
        }
        else
        {
            requests = [ProtocolMagic.GSW1, ProtocolMagic.GSQ1];
            results = [ProtocolMagic.GSS1];
            requestMaximum = PrivacyRoutingLimits.MaximumGroupControlRequestBytes;
            resultMaximum = PrivacyRoutingLimits.MaximumGroupControlResponseBytes;
        }
        Assert.Equal(requests, Strings(row, "requestMagic"));
        Assert.Equal(results, Strings(row, "successMagic"));
        Assert.Equal(requestMaximum, row.GetProperty("maxRequestBytes").GetInt32());
        Assert.Equal(resultMaximum, row.GetProperty("maxSuccessBytes").GetInt32());
    }

    [Fact]
    public void ContactOversizeRejectsBeforeNestedRequestParsing()
    {
        var error = Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingPayloadVerifier.ValidateRequest(new byte[16],
                PrivacyRoutingOperation.ContactResolve,
                new byte[ContactCoordinationOnionCodec.MaximumRequestBytes + 1]));
        Assert.Equal(PrivacyRoutingProtocolError.InvalidLength, error.Error);
    }

    [Theory]
    [InlineData(2, 1_048_556)]
    [InlineData(4, 131_072)]
    [InlineData(5, 65_535)]
    public void TerminalBodyMaximumAndOneByteOverflowExecuteActualFraming(int id, int maximum)
    {
        var operation = (PrivacyRoutingOperation)id;
        var body = new byte[maximum];
        var result = PrivacyRoutingTerminalResult.Success(operation, body);
        Assert.Equal(maximum + 20, PrivacyRoutingResultCodec.Encode(result).Length);
        var error = Assert.Throws<PrivacyRoutingProtocolException>(() =>
            PrivacyRoutingTerminalResult.Success(operation, new byte[maximum + 1]));
        Assert.Equal(PrivacyRoutingProtocolError.InvalidLength, error.Error);
    }

    private static string[] Strings(JsonElement row, string property) =>
        row.GetProperty(property).EnumerateArray().Select(value => value.GetString()!).ToArray();

    private static string FindVectors()
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "docs", "survival-program",
                "releases", "v3.0.0", "specs", "onion-01.vectors.json");
            if (File.Exists(candidate)) return candidate;
        }
        throw new FileNotFoundException("The actual root ONION vector input is absent.");
    }
}
