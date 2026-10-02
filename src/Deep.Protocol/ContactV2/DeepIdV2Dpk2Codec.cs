using System.Security.Cryptography;
using Deep.Protocol.MessagingWire;

namespace Deep.Protocol.ContactV2;

/// <summary>
/// Exact DID2-generation DPK2 bytes. A parsed offering is not claim or
/// publication authority; its device signatures and current directory
/// closure must be verified before use.
/// </summary>
public sealed class ParsedDpk2V2
{
    private readonly byte[] canonical;
    private readonly Dpk2Record record;

    internal ParsedDpk2V2(byte[] canonical, Dpk2Record record)
    {
        this.canonical = canonical;
        this.record = record;
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> ExactHash => SHA256.HashData(
        MessagingWireCryptographicInputs.DomainHashInput(
            MessagingWireCryptographicInputs.ExactDpk2Domain, canonical));
    public ReadOnlyMemory<byte> NetworkId => record.NetworkId;
    public ReadOnlyMemory<byte> ResponderAccountId => record.ResponderAccountId;
    public ReadOnlyMemory<byte> ResponderDeviceId => record.ResponderDeviceId;
    public ReadOnlyMemory<byte> ResponderDpd1Reference => record.ResponderDpd1Ref;
    public ReadOnlyMemory<byte> DeviceDirectoryHeadHash => record.DeviceDirectoryHeadHash;
    public ReadOnlyMemory<byte> DeviceAgreementPublicKey => record.DeviceAgreementPublicKey;
    public ReadOnlyMemory<byte> OneTimePrekeyId => record.OneTimeX25519PrekeyId;
    public ReadOnlyMemory<byte> SignedX25519PrekeyId => record.SignedX25519PrekeyId;
    public ReadOnlyMemory<byte> MlKemPrekeyId => record.MlKemPrekeyId;
    public Dpk2PrekeyKind Kind => record.MlKemKind;
    public ushort ReuseLimit => record.ReuseLimit;
    public ulong ResponderDeviceGeneration => record.ResponderDeviceGeneration;
    public ulong DeviceDirectoryGeneration => record.DeviceDirectoryGeneration;
    public ulong PrekeyServiceGeneration => record.PrekeyServiceGeneration;
    public ulong InventoryEpoch => record.InventoryEpoch;
    public ulong NotBefore => record.NotBefore;
    public ulong IssuedAt => record.IssuedAt;
    public ulong ExpiresAt => record.ExpiresAt;

    internal Dpk2Record Record => record;
}

/// <summary>
/// Closed DID2 DPK2 envelope. V1 version/suite bytes cannot be decoded here.
/// This codec does not mint signer or inventory authority.
/// </summary>
public static class DeepIdV2Dpk2Codec
{
    public const ushort Version = 2;
    public const ushort Suite = 0x0301;
    public static bool RuntimeActivation => false;

    public static byte[] Encode(Dpk2Record record) =>
        Dpk2Codec.EncodeForEnvelope(record, Version, Suite);

    public static ParsedDpk2V2 Decode(ReadOnlySpan<byte> canonical)
    {
        var record = Dpk2Codec.DecodeForEnvelope(canonical, Version, Suite);
        return new ParsedDpk2V2(canonical.ToArray(), record);
    }

    public static byte[] GetX25519SignedPrekeySignatureInput(Dpk2Record record) =>
        MessagingWireCryptographicInputs.SignatureInput(
            MessagingWireCryptographicInputs.X25519SignedPrekeyDomain,
            Dpk2Codec.GetX25519SignedPrekeyProjectionForEnvelope(
                record, Version, Suite), Suite);

    public static byte[] GetMlKemPrekeySignatureInput(Dpk2Record record) =>
        MessagingWireCryptographicInputs.SignatureInput(
            MessagingWireCryptographicInputs.MlKemPrekeyDomain,
            Dpk2Codec.GetMlKemPrekeyProjectionForEnvelope(
                record, Version, Suite), Suite);

    public static byte[] GetPrekeyBundleSignatureInput(Dpk2Record record) =>
        MessagingWireCryptographicInputs.SignatureInput(
            MessagingWireCryptographicInputs.PrekeyBundleDomain,
            Dpk2Codec.GetUnsignedBundleProjectionForEnvelope(
                record, Version, Suite), Suite);
}
