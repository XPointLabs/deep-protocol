using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Deep.Protocol.ContactV1;

var repository = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
var specifications = Path.Combine(
    Directory.GetParent(repository)!.FullName,
    "docs", "survival-program", "releases", "v3.0.0", "specs");
var vectorsPath = Path.Combine(specifications, "contact-codec-v1.vectors.json");
var anchorPath = Path.Combine(specifications, "contact-codec-v1.vectors.anchor.json");
var testPath = Path.Combine(repository, "tests", "Deep.Protocol.Tests", "ContactV1", "ContactCodecTests.cs");

var xmg = Record("XMG1",
    Bytes(16, 0x11), Bytes(32, 0x21), Bytes(32, 0x31), Bytes(32, 0x41),
    Bytes(32, 0x51), [1], Reference("PMT2", 0x61), Bytes(32, 0x71),
    U64(100), U64(120), Bytes(32, 0x81), Bytes(64, 0x91));
var xmc = Record("XMC1",
    Bytes(16, 0x11), Bytes(32, 0x21), U16(2), U64(110), SHA256.HashData(xmg),
    U64(120), new byte[32], []);
var pma = Record("PMA2",
    Bytes(16, 0x11), U64(0), new byte[32], Bytes(32, 0x21), Bytes(32, 0x31),
    Bytes(32, 0x41), U64(1), U32(3_600), U16(1), U64(90), U64(95), U64(800),
    Reference("XNA1", 0x51), Bytes(32, 0x61), [1],
    Join(Bytes(32, 0x71), Bytes(64, 0x81)));

var root = JsonNode.Parse(File.ReadAllText(vectorsPath))!.AsObject();
var records = root["records"]!.AsArray();
Upsert(records, "xmg1-canonical-grammar", xmg);
Upsert(records, "xmc1-failure-grammar", xmc);
Upsert(records, "pma2-canonical", pma, afterId: "xra1-canonical");
var bounds = root["canonicalBounds"]!.AsObject();
bounds["XMG1"] = new JsonObject { ["recordBytes"] = 435 };
bounds["XMC1"] = new JsonObject { ["failureRecordBytes"] = 206, ["successRecordBytes"] = 478 };
bounds["PMA2"] = new JsonObject { ["minimumRecordBytes"] = 497, ["maximumRecordBytes"] = 1169 };

var options = new JsonSerializerOptions { WriteIndented = true };
File.WriteAllText(vectorsPath, root.ToJsonString(options) + Environment.NewLine, new UTF8Encoding(false));
var canonical = File.ReadAllText(vectorsPath).Replace("\r\n", "\n", StringComparison.Ordinal);
var manifestHash = Hex(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
var anchor = JsonNode.Parse(File.ReadAllText(anchorPath))!.AsObject();
anchor["sha256"] = manifestHash;
File.WriteAllText(anchorPath, anchor.ToJsonString(options) + Environment.NewLine, new UTF8Encoding(false));
var test = File.ReadAllText(testPath);
var replaced = 0;
test = Regex.Replace(
    test,
    "Assert\\.Equal\\(\"[0-9a-f]{64}\"",
    match => replaced++ < 2 ? $"Assert.Equal(\"{manifestHash}\"" : match.Value);
if (replaced < 2)
    throw new InvalidDataException("ContactCodecTests manifest assertions were not found.");
File.WriteAllText(testPath, test, new UTF8Encoding(false));
Console.WriteLine(manifestHash);

static void Upsert(JsonArray records, string id, byte[] exact, string? afterId = null)
{
    var record = ContactCodec.Decode(exact);
    var hash = Hex(SHA256.HashData(exact));
    var node = new JsonObject
    {
        ["id"] = id,
        ["target"] = record.Magic,
        ["fixtureBytesHex"] = Convert.ToHexString(exact).ToLowerInvariant(),
        ["sha256"] = hash,
        ["artifactHash"] = Convert.ToHexString(record.ArtifactHash.Span).ToLowerInvariant(),
        ["coreHash"] = Convert.ToHexString(record.CoreHash.Span).ToLowerInvariant(),
    };
    var existing = records.Select((value, index) => (value, index))
        .SingleOrDefault(pair => pair.value?["id"]?.GetValue<string>() == id);
    if (existing.value is not null)
    {
        records[existing.index] = node;
        return;
    }
    var insertion = afterId is null
        ? records.Count
        : records.Select((value, index) => (value, index))
            .Single(pair => pair.value?["id"]?.GetValue<string>() == afterId).index + 1;
    records.Insert(insertion, node);
}

static byte[] Record(string magic, params byte[][] fields)
{
    using var stream = new MemoryStream();
    stream.Write(Encoding.ASCII.GetBytes(magic));
    WriteU16(stream, 1);
    WriteU16(stream, 0x0201);
    WriteU16(stream, checked((ushort)fields.Length));
    WriteU16(stream, 0);
    for (var index = 0; index < fields.Length; index++)
    {
        WriteU16(stream, checked((ushort)(index + 1)));
        WriteU16(stream, 0);
        WriteU32(stream, checked((uint)fields[index].Length));
        stream.Write(fields[index]);
    }
    return stream.ToArray();
}

static byte[] Reference(string magic, byte marker) =>
    Join(Encoding.ASCII.GetBytes(magic), U16(1), Bytes(32, marker));
static byte[] Bytes(int length, byte marker) => Enumerable.Repeat(marker, length).ToArray();
static byte[] Join(params byte[][] values) => values.SelectMany(static value => value).ToArray();
static string Hex(ReadOnlySpan<byte> value) => Convert.ToHexString(value).ToLowerInvariant();
static byte[] U16(ushort value) { var bytes = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(bytes, value); return bytes; }
static byte[] U32(uint value) { var bytes = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(bytes, value); return bytes; }
static byte[] U64(ulong value) { var bytes = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(bytes, value); return bytes; }
static void WriteU16(Stream stream, ushort value) => stream.Write(U16(value));
static void WriteU32(Stream stream, uint value) => stream.Write(U32(value));
