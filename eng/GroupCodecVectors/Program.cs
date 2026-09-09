using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Deep.Protocol.GroupV1;
using Sodium;

if (args.Length != 2 || args[0] is not ("emit" or "check"))
    throw new ArgumentException("Usage: GroupCodecVectors <emit|check> <vector-json>");
var path = Path.GetFullPath(args[1]);
if (args[0] == "emit") Emit(path);
Check(path);

static void Emit(string path)
{
    var root = JsonNode.Parse(File.ReadAllText(path))!.AsObject();
    root["status"] = "FROZEN_TARGET_NOT_ACTIVE";
    var records = root["records"]!.AsArray();
    records.Clear();
    var network = Bytes(16, 0x91);
    var key = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x51));
    var group = Bytes(32,0x11); var account=Bytes(32,0x21); var device=Bytes(32,0x31);var dpd=Ref("DPD1",0x41);
    var invitationFields=new byte[][]{network,group,Bytes(32,0x12),U64(0),Bytes(32,0x13),account,device,dpd,Bytes(32,0x22),new byte[]{3},Ref("ADC1",0x23),Ref("ADH1",0x24),Bytes(32,0x25),Bytes(32,0x26),Ref("DRS1",0x27),U64(100),U64(200),new byte[64]};
    var invitation=Sign("GIV1",invitationFields,18,key);Add(records,"giv1-canonical","GIV1",invitation,key.PublicKey);
    var acceptanceFields=new byte[][]{network,group,invitationFields[2],RefHash("GIV1",RecordHash("GIV1",invitation)),invitationFields[8],Bytes(32,0x32),Ref("DPD1",0x42),invitationFields[10],invitationFields[11],invitationFields[12],invitationFields[13],invitationFields[14],U64(120),U64(190),new byte[64]};
    var acceptance=Sign("GIA1",acceptanceFields,15,key);Add(records,"gia1-canonical","GIA1",acceptance,key.PublicKey);
    var proposalFields=new byte[][]{network,group,U64(0),Bytes(32,0x14),Bytes(32,0x15),account,device,dpd,U16(6),Profile("vector-group",1,3600),U64(100),U64(200),new byte[64]};
    var proposal=Sign("DGP1",proposalFields,13,key);Add(records,"dgp1-canonical","DGP1",proposal,key.PublicKey);
    var member=Member(account,device,dpd);
    var commitFields=new byte[][]{network,group,U16(1),U64(0),new byte[32],account,device,dpd,U16(0),Array.Empty<byte>(),U16(1),member,Encoding.UTF8.GetBytes("vector-group"),new byte[]{0},U32(3600),U64(120),new byte[64]};
    var commit=Sign("DGC1",commitFields,17,key);Add(records,"dgc1-canonical","DGC1",commit,key.PublicKey);
    var transferFields=new byte[][]{network,group,RefHash("DGC1",RecordHash("DGC1",commit)),U64(0),device,Bytes(32,0x33),Ref("DPD1",0x43),Bytes(32,0x34),Ref("DRS1",0x35),Bytes(32,0x36),U64(120),U64(180),Ref("DPA1",0x37),new byte[64]};
    var transfer=Sign("DGT1",transferFields,14,key);Add(records,"dgt1-canonical","DGT1",transfer,key.PublicKey);
    var message=Encode("DGM1",Enumerable.Range(1,12).ToArray(),[network,group,U64(0),RecordHash("DGC1",commit),Bytes(32,0x16),account,device,U64(1),U64(120000),U64(180000),U16(1),Encoding.UTF8.GetBytes("hello")]);Add(records,"dgm1-canonical","DGM1",message,null);
    var package=Encode("GCP1",Enumerable.Range(1,11).ToArray(),[network,group,U64(0),Lp(commit),U16(0),Array.Empty<byte>(),U32(0),Array.Empty<byte>(),U16(0),Array.Empty<byte>(),Array.Empty<byte>()]);Add(records,"gcp1-canonical","GCP1",package,null);
    var frame=Encode("GCF1",Enumerable.Range(1,7).ToArray(),[RecordHash("GCP1",package),U32(checked((uint)package.Length)),U32(24576),U32(0),U32(1),SHA256.HashData(package),Lp(package)]);Add(records,"gcf1-canonical","GCF1",frame,null);
    var gsrFields = new byte[][] { network,Bytes(32,0x92),Bytes(32,0x93),U64(0),new byte[32],Ref("PMT2",0x94),Bytes(32,0x95),Bytes(32,0x96),Bytes(32,0x97),Bytes(32,0x98),Ref("DPD1",0x99),U64(100),U64(200),Bytes(64,0xa0) };
    var placeholder = GroupCodec.Decode("GSR1", Encode("GSR1", Enumerable.Range(1,14).ToArray(), gsrFields));
    gsrFields[13] = PublicKeyAuth.SignDetached(placeholder.SignatureInput.ToArray(), key.PrivateKey);
    Add(records,"gsr1-current-owner-signed","GSR1",Encode("GSR1",Enumerable.Range(1,14).ToArray(),gsrFields),key.PublicKey);
    var sealedChunk=Bytes(128,0xa1);
    Add(records,"gsw1-sealed-chunk-cas","GSW1",Encode("GSW1",[1,2,3,4,5,6,16,17,18,19,20,21,22],[network,Bytes(32,1),Bytes(32,2),Bytes(32,3),U64(100),U64(200),Bytes(32,4),Bytes(32,5),U64(1),new byte[32],SHA256.HashData(sealedChunk),Lp(sealedChunk),U64(300)]),null);
    Add(records,"gsq1-class4-catchup","GSQ1",Encode("GSQ1",[1,2,3,4,5,6,16,17,18,19,20],[network,Bytes(32,6),Bytes(32,7),Bytes(32,8),U64(100),U64(200),Bytes(32,9),Bytes(32,10),U64(0),U16(64),U16(4)]),null);
    Add(records,"gss1-write-committed","GSS1",Encode("GSS1",[1,2,3,4,5,6,7,8,16,17,18,19,20],[network,Bytes(32,6),Bytes(32,11),U16(1),new byte[]{1},U64(150),U32(0),U16(4),new byte[]{1},U64(1),Bytes(32,12),U64(1),Bytes(96,13)]),null);

    var hostile = root["hostileCases"]!.AsArray();
    for (var index=hostile.Count-1;index>=0;index--) if(hostile[index]!["id"]!.GetValue<string>()=="gsr1-signature")hostile.RemoveAt(index);
    var badGsr=gsrFields.Select(static value=>value.ToArray()).ToArray();badGsr[13][0]^=0x80;
    hostile.Add(new JsonObject{{"id","gsr1-signature"},{"target","GSR1"},{"fixtureBytesHex",Hex(Encode("GSR1",Enumerable.Range(1,14).ToArray(),badGsr))},{"expectedCode","DeviceSignatureVerificationFailed"},{"signerPublicKeyHex",Hex(key.PublicKey)}});
    File.WriteAllText(path,root.ToJsonString(new JsonSerializerOptions{WriteIndented=true})+Environment.NewLine,new UTF8Encoding(false));
}

static void Check(string path)
{
    using var json=JsonDocument.Parse(File.ReadAllBytes(path));var records=json.RootElement.GetProperty("records").EnumerateArray().ToArray();
    var expected=new HashSet<string>(["GIV1","GIA1","DGP1","DGC1","DGM1","DGT1","GCP1","GCF1","GSR1","GSW1","GSQ1","GSS1"],StringComparer.Ordinal);
    if(records.Length!=12||!expected.SetEquals(records.Select(x=>x.GetProperty("target").GetString()!)))throw new InvalidDataException("Canonical GROUP-CODEC target set is not exact.");
    foreach(var vector in records)
    {
        var magic=vector.GetProperty("target").GetString()!;var bytes=Convert.FromHexString(vector.GetProperty("fixtureBytesHex").GetString()!);var record=GroupCodec.Decode(bytes);
        if(record.Magic!=magic||!CryptographicOperations.FixedTimeEquals(record.ArtifactHash.Span,Convert.FromHexString(vector.GetProperty("recordHash32").GetString()!)))throw new InvalidDataException($"Vector mismatch: {magic}");
        if(vector.GetProperty("signerPublicKeyHex").ValueKind!=JsonValueKind.Null){var tag=SignatureTag(magic);if(!PublicKeyAuth.VerifyDetached(record.Field(tag).ToArray(),record.SignatureInput.ToArray(),Convert.FromHexString(vector.GetProperty("signerPublicKeyHex").GetString()!)))throw new InvalidDataException($"Signature mismatch: {magic}");}
    }
    foreach(var hostile in json.RootElement.GetProperty("hostileCases").EnumerateArray())
    {
        var magic=hostile.GetProperty("target").GetString()!;var bytes=Convert.FromHexString(hostile.GetProperty("fixtureBytesHex").GetString()!);var expectedCode=hostile.GetProperty("expectedCode").GetString()!;
        if(expectedCode=="NonCanonicalReserved"){try{_ = GroupCodec.Decode(bytes);throw new InvalidDataException($"Hostile vector accepted: {hostile.GetProperty("id").GetString()}");}catch(GroupFormatException error)when(error.Code==expectedCode){}}
        else{var record=GroupCodec.Decode(bytes);var key=Convert.FromHexString(hostile.GetProperty("signerPublicKeyHex").GetString()!);if(PublicKeyAuth.VerifyDetached(record.Field(SignatureTag(magic)).ToArray(),record.SignatureInput.ToArray(),key))throw new InvalidDataException($"Hostile signature accepted: {magic}");}
    }
    if(GroupCodec.RuntimeActivation||!GroupCodec.AccountDirectoryCapabilityAvailable)throw new InvalidDataException("GROUP-CODEC activation/capability state is inconsistent.");
    var productionAssembly=typeof(GroupCodec).Assembly;
    if(productionAssembly.GetCustomAttributes(typeof(InternalsVisibleToAttribute),false).Length!=0)throw new InvalidDataException("Production Deep.Protocol exposes InternalsVisibleTo.");
    if(typeof(VerifiedGroupTransition).GetConstructors().Length!=0||typeof(GroupIdentityClosure).GetConstructors().Length!=0)throw new InvalidDataException("A verified GROUP capability has a public constructor.");
    Console.WriteLine($"GROUP-CODEC vectors verified: {records.Length} records; runtime inactive; production directory capability available.");
}

static void Add(JsonArray records,string id,string magic,byte[] bytes,byte[]? key)=>records.Add(new JsonObject{{"id",id},{"target",magic},{"fixtureBytesHex",Hex(bytes)},{"recordHash32",Hex(RecordHash(magic,bytes))},{"signerPublicKeyHex",key is null?null:Hex(key)}});
static byte[] Sign(string magic,byte[][] fields,int signatureTag,KeyPair key){fields=fields.Select(x=>x.ToArray()).ToArray();fields[signatureTag-1]=Bytes(64,0xa0);var placeholder=GroupCodec.Decode(Encode(magic,Enumerable.Range(1,fields.Length).ToArray(),fields));fields[signatureTag-1]=PublicKeyAuth.SignDetached(placeholder.SignatureInput.ToArray(),key.PrivateKey);return Encode(magic,Enumerable.Range(1,fields.Length).ToArray(),fields);}
static int SignatureTag(string magic)=>magic switch{"GIV1"=>18,"GIA1"=>15,"DGP1"=>13,"DGC1"=>17,"DGT1"=>14,"GSR1"=>14,_=>throw new InvalidOperationException()};
static byte[] RecordHash(string magic,byte[] bytes)=>DomainHash($"Deep/Application/V1/record-hash/{magic}",bytes);
static byte[] DomainHash(string label,byte[] value){var l=Encoding.ASCII.GetBytes(label);var p=new byte[l.Length+5+value.Length];l.CopyTo(p,0);BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(l.Length+1),checked((uint)value.Length));value.CopyTo(p,l.Length+5);return SHA256.HashData(p);}
static byte[] Encode(string magic,int[] tags,IReadOnlyList<byte[]> fields){var b=new byte[12+fields.Sum(x=>8+x.Length)];Encoding.ASCII.GetBytes(magic).CopyTo(b,0);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(4),1);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(6),0x0201);BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(8),checked((ushort)fields.Count));var at=12;for(var i=0;i<fields.Count;i++){BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(at),checked((ushort)tags[i]));BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(at+4),checked((uint)fields[i].Length));at+=8;fields[i].CopyTo(b,at);at+=fields[i].Length;}return b;}
static byte[] Ref(string magic,byte seed){var b=new byte[38];Encoding.ASCII.GetBytes(magic).CopyTo(b,0);b[5]=1;Bytes(32,seed).CopyTo(b,6);return b;}
static byte[] RefHash(string magic,byte[] hash){var b=new byte[38];Encoding.ASCII.GetBytes(magic).CopyTo(b,0);b[5]=1;hash.CopyTo(b,6);return b;}
static byte[] Member(byte[] account,byte[] device,byte[] dpd){var body=new byte[290];account.CopyTo(body,0);body[32]=1;Ref("ADC1",0x61).CopyTo(body,33);Ref("ADH1",0x62).CopyTo(body,71);Bytes(32,0x63).CopyTo(body,109);U64(1).CopyTo(body,141);Bytes(32,0x64).CopyTo(body,149);Ref("DRS1",0x65).CopyTo(body,181);body[219]=1;device.CopyTo(body,220);dpd.CopyTo(body,252);var result=new byte[292];BinaryPrimitives.WriteUInt16BigEndian(result,290);body.CopyTo(result,2);return result;}
static byte[] Profile(string name,byte policy,uint expiry){var value=Encoding.UTF8.GetBytes(name);var result=new byte[2+value.Length+5];BinaryPrimitives.WriteUInt16BigEndian(result,checked((ushort)value.Length));value.CopyTo(result,2);result[2+value.Length]=policy;BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(3+value.Length),expiry);return result;}
static byte[] Lp(byte[] value){var b=new byte[value.Length+4];BinaryPrimitives.WriteUInt32BigEndian(b,checked((uint)value.Length));value.CopyTo(b,4);return b;}
static byte[] Bytes(int n,byte seed)=>Enumerable.Range(0,n).Select(i=>unchecked((byte)(seed+i))).ToArray();
static byte[] U16(ushort value){var b=new byte[2];BinaryPrimitives.WriteUInt16BigEndian(b,value);return b;}
static byte[] U32(uint value){var b=new byte[4];BinaryPrimitives.WriteUInt32BigEndian(b,value);return b;}
static byte[] U64(ulong value){var b=new byte[8];BinaryPrimitives.WriteUInt64BigEndian(b,value);return b;}
static string Hex(byte[] value)=>Convert.ToHexString(value).ToLowerInvariant();
