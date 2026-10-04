using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.XPointNetworkV1;
using Deep.Protocol.Registry;
using Sodium;

namespace Deep.Protocol.Tests.XPointNetworkV1;

public sealed class MailboxGrantRevocationV1FrozenTests
{
    private const string CorpusHash = "b49b4778f01c55870487ba82ba98c33349bc23cefd9608627436f7e940d10314";
    public static IEnumerable<object[]> Positives => Cases("positiveCases");
    public static IEnumerable<object[]> Negatives => Cases("negativeCases");

    [Theory]
    [MemberData(nameof(Positives))]
    public void IndependentSignedVectorMatchesCodecAndRealSignature(string id, JsonElement vector)
    {
        Assert.False(string.IsNullOrEmpty(id));
        var exact = Hex(vector, "recordHex");
        var parsed = MailboxGrantRevocationV1Codec.Decode(exact);
        Assert.Equal(vector.GetProperty("domain").GetByte(), (byte)parsed.Domain);
        Assert.Equal(vector.GetProperty("generation").GetUInt64(), parsed.Generation);
        Assert.Equal(Hex(vector, "coreHashHex"), parsed.CoreHash.ToArray());
        Assert.Equal(Hex(vector, "signatureInputHex"), parsed.SignatureInput.ToArray());
        Assert.Equal(Hex(vector, "recordSha256"), SHA256.HashData(exact));
        Assert.Equal(Hex(vector, "issuerPublicKeyHex"), parsed.Field(4).ToArray());
        Assert.Equal(Hex(vector, "unsignedHex"), parsed.SignatureInput.ToArray()[33..]);
        Assert.True(PublicKeyAuth.VerifyDetached(parsed.Field(12).ToArray(),
            parsed.SignatureInput.ToArray(), parsed.Field(4).ToArray()));
        Assert.Equal(exact, MailboxGrantRevocationV1Codec.Encode(
            Enumerable.Range(1, 11).Select(parsed.Field).ToArray(), parsed.Field(12).Span));
    }

    [Theory]
    [MemberData(nameof(Negatives))]
    public void FrozenMalformedBytesRejectAtDeclaredStage(string id, JsonElement vector)
    {
        Assert.False(string.IsNullOrEmpty(id));
        var rejected = Assert.Throws<ApplicationCoreFormatException>(() =>
            MailboxGrantRevocationV1Codec.Decode(Hex(vector, "recordHex")));
        Assert.Equal(vector.GetProperty("stage").GetString(), rejected.Stage.ToString());
        Assert.Equal(vector.GetProperty("rejection").GetString(), rejected.Rejection.ToString());
    }

    [Fact]
    public void MachineContractPinsActualWidthsDomainsCapacityAndUnactivatedLifecycle()
    {
        using var manifest = Read("mailbox-grant-revocation-v1.vectors.json");
        var corpus = manifest.RootElement;
        Assert.Equal(new[] { "deposit-empty", "retrieve-empty", "deposit-revoked", "deposit-successor" },
            corpus.GetProperty("positiveCases").EnumerateArray().Select(x => x.GetProperty("id").GetString()));
        Assert.Equal(new[] { "version", "suite", "reserved", "unknown-tag", "field-length", "count-overflow", "zero-serial", "truncated" },
            corpus.GetProperty("negativeCases").EnumerateArray().Select(x => x.GetProperty("id").GetString()));
        using var registry = Read("mailbox-grant-revocation-v1.registry.json");
        var contract = registry.RootElement;
        Assert.Equal("DR-0083", contract.GetProperty("decision").GetString());
        Assert.Equal("MGR1", contract.GetProperty("magic").GetString());
        Assert.Equal(1, contract.GetProperty("version").GetInt32());
        Assert.Equal("0x0201", contract.GetProperty("suite").GetString());
        Assert.Equal("FROZEN_TARGET_NOT_ACTIVE", contract.GetProperty("status").GetString());
        Assert.False(contract.GetProperty("runtimeActivation").GetBoolean());
        Assert.False(MailboxGrantRevocationV1Codec.RuntimeActivation);
        Assert.False(MailboxGrantRevocationV1Verifier.RuntimeActivation);
        Assert.Equal("MGR1", DeepProtocolIdentifiers.Magic.MGR1);
        Assert.Equal(ProtocolIdentifierLifecycle.FROZEN_TARGET_NOT_ACTIVE,
            Assert.Single(DeepProtocolRegistryGenerated.Identifiers,
                x => x.Namespace == "magic" && x.CanonicalName == "MGR1").Lifecycle);
        Assert.Equal(MailboxGrantRevocationV1Codec.MinimumBytes, contract.GetProperty("minimumBytes").GetInt32());
        Assert.Equal(MailboxGrantRevocationV1Codec.MaximumBytes, contract.GetProperty("maximumBytes").GetInt32());
        Assert.Equal(MailboxGrantRevocationV1Codec.MaximumSerials, contract.GetProperty("maximumRevokedSerials").GetInt32());
        Assert.Equal(MailboxGrantRevocationV1Codec.MaximumLifetimeSeconds, contract.GetProperty("maximumSnapshotLifetimeSeconds").GetUInt64());
        Assert.Equal("Deep/XPoint/V1/MGR1/issuer", contract.GetProperty("signatureDomain").GetString());
        Assert.Equal("Deep/XPoint/V1/MGR1/core", contract.GetProperty("coreDomain").GetString());
        var fields = contract.GetProperty("fields").EnumerateArray().ToArray();
        Assert.Equal(12, contract.GetProperty("fieldCount").GetInt32());
        Assert.Equal(12, fields.Length);
        var exact = MailboxGrantRevocationV1Codec.Decode(Hex(corpus.GetProperty("positiveCases")[0], "recordHex"));
        Assert.Equal(327, exact.CanonicalBytes.Length);
        for (var i = 0; i < fields.Length; i++)
        {
            Assert.Equal(i + 1, fields[i].GetProperty("tag").GetInt32());
            if (i != 10) Assert.Equal(fields[i].GetProperty("bytes").GetInt32(), exact.Field(i + 1).Length);
        }
        Assert.Equal(16, fields[10].GetProperty("elementBytes").GetInt32());
        Assert.Equal(10, fields[10].GetProperty("countTag").GetInt32());
        Assert.True(fields[10].GetProperty("strictlyIncreasing").GetBoolean());
        Assert.True(fields[10].GetProperty("nonzeroElements").GetBoolean());
        Assert.Equal(1, fields[5].GetProperty("zeroIffGeneration").GetInt32());
        Assert.Equal(Enumerable.Range(1, 11), contract.GetProperty("unsignedTags").EnumerateArray().Select(x => x.GetInt32()));
        Assert.False(contract.GetProperty("clientWireChanged").GetBoolean());
        Assert.False(contract.GetProperty("networkDistributionWireChanged").GetBoolean());
        var initial = contract.GetProperty("initialEnrollment");
        Assert.Equal(4, initial.EnumerateObject().Count());
        Assert.Equal("explicit genuinely new protected host scope only", initial.GetProperty("scope").GetString());
        Assert.Equal("fresh canonical current-role issuer-signed snapshot at any generation >=1", initial.GetProperty("snapshot").GetString());
        Assert.Equal("immutable exact bytes; restored floor rejects lower generation or changed bytes at initial generation", initial.GetProperty("initialPin").GetString());
        Assert.Equal("exact replay or sequential verified successor only; no reset or gap bypass", initial.GetProperty("existingFloor").GetString());
        Assert.Null(typeof(MailboxGrantRevocationV1Verifier).GetMethod("PlanGenesisAsync"));
    }

    private static IEnumerable<object[]> Cases(string property)
    {
        var path = XPointNetworkFrozenVectorManifest.FindSpec("mailbox-grant-revocation-v1.vectors.json");
        var text = File.ReadAllText(path).Replace("\r\n", "\n", StringComparison.Ordinal);
        Assert.Equal(CorpusHash, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(text))).ToLowerInvariant());
        using var document = JsonDocument.Parse(text);
        return document.RootElement.GetProperty(property).EnumerateArray()
            .Select(x => new object[] { x.GetProperty("id").GetString()!, x.Clone() }).ToArray();
    }
    private static JsonDocument Read(string name) => JsonDocument.Parse(
        File.ReadAllText(XPointNetworkFrozenVectorManifest.FindSpec(name)));
    private static byte[] Hex(JsonElement vector, string property) =>
        Convert.FromHexString(vector.GetProperty(property).GetString()!);
}
