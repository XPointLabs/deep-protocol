using System.Security.Cryptography;
using System.Text.Json;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

// Public deterministic test seeds only. Never accept operator custody as input.
if (args.Length != 1 || Path.GetFileName(args[0]) != "mailbox-authorization-v3.json")
    throw new ArgumentException("Supply the exact V3 golden-vector destination.");
var crypto = new SodiumMailboxCapabilityCrypto();
var issuerSeed = Range(0x10, 32);
var holderSeed = Range(0x40, 32);
var vectors = new List<object>();
foreach (var operation in Enum.GetValues<MailboxAuthenticatedOperation>())
{
    var domain = operation == MailboxAuthenticatedOperation.Store
        ? MailboxCapabilityDomain.Deposit : MailboxCapabilityDomain.Retrieve;
    var grant = crypto.SignGrant(new MailboxAuthenticatedGrant
    {
        Domain = domain, Lifecycle = MailboxCapabilityLifecycle.Active,
        Generation = 7, NetworkId = Range(0x70, 16), Epoch = 11,
        Serial = Range(0x80, 16), NotBeforeUnixSeconds = 1000, ExpiresAtUnixSeconds = 1100,
        OverlapUntilUnixSeconds = 0,
        PlacementCommitment = MailboxPlacementCommitment.Compute(new BlindedPlacementId(Range(0x90, 32))),
        MembershipCommitment = Range(0xb0, 32), SelectionInput = Range(0xa0, 32),
        IssuerPublicKey = crypto.GetPublicKey(issuerSeed), HolderPublicKey = crypto.GetPublicKey(holderSeed),
        IssuerSignature = ReadOnlyMemory<byte>.Empty,
    }, issuerSeed);
    var binding = operation switch
    {
        MailboxAuthenticatedOperation.Store => MailboxAuthenticatedRequestTranscript.ForStore(new MailboxEncryptedEnvelope
        {
            Epoch = 11, MailboxId = new BlindedMailboxId(Range(0x20, 32)),
            PlacementId = new BlindedPlacementId(Range(0x90, 32)), OperationId = Range(0xd0, 16),
            DeduplicationDigest = Range(0xe0, 32), CreatedAtUnixSeconds = 1000,
            ExpiresAtUnixSeconds = 1060, Ciphertext = Range(1, 64),
        }),
        MailboxAuthenticatedOperation.Retrieve => MailboxAuthenticatedRequestTranscript.ForRetrieve(
            11, Range(0xd0, 16), new BlindedMailboxId(Range(0x20, 32)),
            new BlindedPlacementId(Range(0x90, 32)), 42, 10, Range(1, 8)),
        MailboxAuthenticatedOperation.Ack => MailboxAuthenticatedRequestTranscript.ForAck(
            11, Range(0xd0, 16), new BlindedMailboxId(Range(0x20, 32)),
            new BlindedPlacementId(Range(0x90, 32)), true, [],
            [new MailboxAcknowledgement { Cursor = 42, EnvelopeDigest = Range(0xe0, 32) }]),
        _ => throw new ArgumentOutOfRangeException(),
    };
    var presentation = crypto.SignPresentation(grant, binding, 9, holderSeed);
    var encoded = MailboxAuthenticatedCapabilityCodec.EncodePresentation(presentation);
    if (operation == MailboxAuthenticatedOperation.Store)
        vectors.Add(new
        {
            id = "deep-extension/mailbox-capability/v3/deposit-store",
            kind = "MCG3 issuer plus MCP3 holder Ed25519 signatures", hex = Hex(encoded),
        });
    var outer = MailboxAuthenticatedClientRequestCodec.Encode(new() { Binding = binding, Presentation = presentation });
    vectors.Add(new
    {
        id = $"deep-extension/mailbox-authenticated/v3/MAU3-{operation.ToString().ToLowerInvariant()}-length-{outer.Length}",
        kind = "sha256-complete-canonical-frame", hex = Hex(SHA256.HashData(outer)),
    });
}
var manifest = new
{
    name = "Selector-bound mailbox V3 Ed25519 golden vectors",
    sourceRepository = "XPointLabs/deep-protocol",
    sourceCommit = "DR-0081 deterministic public test seeds; no production key",
    vectors,
};
File.WriteAllText(Path.GetFullPath(args[0]), JsonSerializer.Serialize(manifest,
    new JsonSerializerOptions { WriteIndented = true }) + "\n");
Console.WriteLine($"Generated {vectors.Count} V3 vectors.");
static byte[] Range(int start, int length) => Enumerable.Range(start, length).Select(x => (byte)x).ToArray();
static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
