using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sodium;

// Independent reference serialization, not the product encoder. Fixed PUBLIC test
// seeds only; no operator custody, environment configuration or network input.
if (args.Length != 1 || Path.GetFileName(args[0]) != "mailbox-grant-revocation-v1.vectors.json")
    throw new ArgumentException("Supply the exact MGR1 golden-vector destination.");
var positives = new List<object>();
var first = Add("deposit-empty", 1, 1, new byte[32], 190, []);
Add("retrieve-empty", 2, 1, new byte[32], 190, []);
var revoked = Add("deposit-revoked", 1, 1, new byte[32], 190, [Repeat(16, 0x51)]);
Add("deposit-successor", 1, 2, revoked.Core, 195, [Repeat(16, 0x51), Repeat(16, 0x52)]);
var negatives = new List<object>();
Bad("version", first.Exact, x => x[5] = 2, "FixedHeader", "WrongVersion");
Bad("suite", first.Exact, x => x[7] = 2, "FixedHeader", "WrongSuite");
Bad("reserved", first.Exact, x => x[11] = 1, "FixedHeader", "ReservedNotZero");
Bad("unknown-tag", first.Exact, x => x[13] = 0, "FieldHeaders", "UnknownTag");
Bad("field-length", first.Exact, x => BinaryPrimitives.WriteUInt32BigEndian(x.AsSpan(16, 4), uint.MaxValue), "FieldLengths", "InvalidFieldLength");
Bad("count-overflow", first.Exact, x => BinaryPrimitives.WriteUInt32BigEndian(x.AsSpan(243, 4), uint.MaxValue), "SemanticFields", "CrossFieldMismatch");
Bad("zero-serial", revoked.Exact, x => x.AsSpan(255, 16).Clear(), "SemanticFields", "CrossFieldMismatch");
negatives.Add(new { id = "truncated", recordHex = Hex(first.Exact[..^1]), stage = "ExactTotalSize", rejection = "InvalidTotalSize" });
var manifest = new
{
    schemaVersion = 1, decision = "DR-0083", status = "FROZEN_TARGET_NOT_ACTIVE", runtimeActivation = false,
    reference = "Independent fixed-width writer; public test seeds e1/e2 repeated 32 times; not production authority",
    positiveCases = positives, negativeCases = negatives,
};
File.WriteAllText(Path.GetFullPath(args[0]), JsonSerializer.Serialize(manifest,
    new JsonSerializerOptions { WriteIndented = true, NewLine = "\n" }) + "\n", new UTF8Encoding(false));
Console.WriteLine($"Generated {positives.Count} signed MGR1 vectors and {negatives.Count} malformed vectors.");

(byte[] Exact, byte[] Core) Add(string id, byte role, ulong generation, byte[] predecessor, ulong issued, byte[][] serials)
{
    var key = PublicKeyAuth.GenerateKeyPair(Repeat(32, role == 1 ? (byte)0xe1 : (byte)0xe2));
    try
    {
        byte[][] fields = [Repeat(16, 0x11), [.. "PMA2"u8, 0, 1, .. Repeat(32, 0x22)], [role], key.PublicKey,
            U64(generation), predecessor, U64(issued), U64(issued), U64(230), U32((uint)serials.Length),
            serials.SelectMany(x => x).ToArray()];
        var unsigned = Frame(fields);
        var input = SignatureInput(unsigned);
        var signature = PublicKeyAuth.SignDetached(input, key.PrivateKey);
        var exact = Frame([.. fields, signature]);
        var core = CoreHash(unsigned);
        positives.Add(new { id, domain = role, generation, recordHex = Hex(exact), unsignedHex = Hex(unsigned),
            signatureInputHex = Hex(input), coreHashHex = Hex(core), recordSha256 = Hex(SHA256.HashData(exact)),
            issuerPublicKeyHex = Hex(key.PublicKey) });
        return (exact, core);
    }
    finally { CryptographicOperations.ZeroMemory(key.PrivateKey); }
}
void Bad(string id, byte[] source, Action<byte[]> mutate, string stage, string rejection)
{
    var bytes = source.ToArray(); mutate(bytes);
    negatives.Add(new { id, recordHex = Hex(bytes), stage, rejection });
}
static byte[] Frame(byte[][] fields)
{
    var bytes = new byte[12 + fields.Length * 8 + fields.Sum(x => x.Length)];
    "MGR1"u8.CopyTo(bytes); BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 1);
    BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), 0x0201);
    BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(8), (ushort)fields.Length);
    var offset = 12;
    for (var index = 0; index < fields.Length; index++)
    {
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), (ushort)(index + 1));
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 4), (uint)fields[index].Length);
        fields[index].CopyTo(bytes, offset + 8); offset += 8 + fields[index].Length;
    }
    return bytes;
}
static byte[] SignatureInput(byte[] unsigned) =>
    [.. Encoding.ASCII.GetBytes("Deep/XPoint/V1/MGR1/issuer"), 0, 2, 1, .. U32((uint)unsigned.Length), .. unsigned];
static byte[] CoreHash(byte[] unsigned) => SHA256.HashData(
    [.. Encoding.ASCII.GetBytes("Deep/XPoint/V1/MGR1/core"), 0, .. U32((uint)unsigned.Length), .. unsigned]);
static byte[] Repeat(int length, byte value) => Enumerable.Repeat(value, length).ToArray();
static byte[] U64(ulong value) { var x = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(x, value); return x; }
static byte[] U32(uint value) { var x = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(x, value); return x; }
static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();
