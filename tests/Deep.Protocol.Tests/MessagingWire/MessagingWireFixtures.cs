using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Deep.Protocol.MessagingWire;
using Sodium;

namespace Deep.Protocol.Tests.MessagingWire;

internal static class MessagingWireFixtures
{
    internal static byte[] Bytes(int length, byte seed)
    {
        var value = new byte[length];
        for (var index = 0; index < value.Length; index++)
            value[index] = unchecked((byte)(seed + index * 17));
        return value;
    }

    internal static Dpk2Record Dpk2(Dpk2PrekeyKind kind)
    {
        var oneTimeId = kind == Dpk2PrekeyKind.OneTime ? Bytes(32, 0xb1) : [];
        var oneTimePublic = kind == Dpk2PrekeyKind.OneTime ? Bytes(32, 0xc1) : [];
        Dpk2Record Build(byte[] xSignature, byte[] mlKemSignature, byte[] bundleSignature) =>
            new(
                Bytes(16, 0x01), Bytes(32, 0x11), Bytes(32, 0x21), 3,
                Bytes(38, 0x31), 5, Bytes(32, 0x41), 7, 11, Bytes(32, 0x51), 13,
                1_700_000_100, 1_700_000_000, 1_700_100_000,
                Bytes(32, 0x61), Bytes(32, 0x71), Bytes(32, 0x81), xSignature,
                oneTimeId, oneTimePublic, Bytes(32, 0xd1), Bytes(1184, 0xe1), kind,
                kind == Dpk2PrekeyKind.OneTime ? (ushort)0 : (ushort)64,
                mlKemSignature, bundleSignature);

        var keyPair = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x5a));
        try
        {
            var placeholder = Build(Bytes(64, 0x91), Bytes(64, 0xf1), Bytes(64, 0xa2));
            var xSignature = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetX25519SignedPrekeySignatureInput(placeholder),
                keyPair.PrivateKey);
            var mlKemSignature = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetMlKemPrekeySignatureInput(placeholder),
                keyPair.PrivateKey);
            var signedPrekeys = Build(xSignature, mlKemSignature, Bytes(64, 0xa2));
            var bundleSignature = PublicKeyAuth.SignDetached(
                MessagingWireCryptographicInputs.GetPrekeyBundleSignatureInput(signedPrekeys),
                keyPair.PrivateKey);
            return Build(xSignature, mlKemSignature, bundleSignature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyPair.PrivateKey);
        }
    }

    internal static byte[] Dpk2SigningPublicKey()
    {
        var keyPair = PublicKeyAuth.GenerateKeyPair(Bytes(32, 0x5a));
        try { return keyPair.PublicKey.ToArray(); }
        finally { CryptographicOperations.ZeroMemory(keyPair.PrivateKey); }
    }

    internal static Dph2Record Dph2(Dpk2Record offering, int ciphertextLength)
    {
        var selected = offering.MlKemKind == Dpk2PrekeyKind.OneTime
            ? Dph2SelectedPrekey.OneTime(
                offering.SignedX25519PrekeyId.Span,
                offering.OneTimeX25519PrekeyId.Span,
                offering.MlKemPrekeyId.Span)
            : Dph2SelectedPrekey.LastResort(
                offering.SignedX25519PrekeyId.Span,
                offering.MlKemPrekeyId.Span);
        return new Dph2Record(
            offering.NetworkId.Span,
            Bytes(32, 0x12),
            Bytes(32, 0x22),
            17,
            Bytes(38, 0x32),
            offering.ResponderAccountId.Span,
            offering.ResponderDeviceId.Span,
            offering.ResponderDeviceGeneration,
            MessagingWireCryptographicInputs.ComputeExactDpk2Hash(offering),
            Bytes(32, 0x42),
            Bytes(32, 0x52),
            offering.MlKemKind == Dpk2PrekeyKind.OneTime ? (ushort)0 : (ushort)37,
            Bytes(32, 0x62),
            Bytes(32, 0x72),
            selected,
            Bytes(1088, 0x82),
            Bytes(32, 0x92),
            Bytes(24, 0xa2),
            Dph2InitialCiphertext.Import(Bytes(ciphertextLength, 0xb2)));
    }

    internal static Dtr2Fixture Dtr2(Dtr2BraidMessageKind kind)
    {
        Dtr2BraidMessage message;
        byte[] payload;
        switch (kind)
        {
            case Dtr2BraidMessageKind.None:
                message = Dtr2BraidMessage.None();
                payload = [];
                break;
            case Dtr2BraidMessageKind.Header:
                var seed = Bytes(32, 0x13);
                var hash = Bytes(32, 0x23);
                var hmac = Bytes(32, 0x33);
                message = Dtr2BraidMessage.Header(seed, hash, hmac);
                payload = ManualMessagingWire.Concat(seed, hash, hmac);
                break;
            case Dtr2BraidMessageKind.EncapsulationKey:
                payload = Bytes(1152, 0x43);
                message = Dtr2BraidMessage.EncapsulationKey(payload);
                break;
            case Dtr2BraidMessageKind.EncapsulationKeyWithCiphertext1Ack:
                payload = Bytes(1152, 0x53);
                message = Dtr2BraidMessage.EncapsulationKeyWithCiphertext1Ack(payload);
                break;
            case Dtr2BraidMessageKind.Ciphertext1Ack:
                message = Dtr2BraidMessage.Ciphertext1Ack();
                payload = [];
                break;
            case Dtr2BraidMessageKind.Ciphertext1:
                payload = Bytes(960, 0x63);
                message = Dtr2BraidMessage.Ciphertext1(payload);
                break;
            case Dtr2BraidMessageKind.Ciphertext2:
                var ct2 = Bytes(128, 0x73);
                var ctHmac = Bytes(32, 0x83);
                message = Dtr2BraidMessage.Ciphertext2(ct2, ctHmac);
                payload = ManualMessagingWire.Concat(ct2, ctHmac);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(kind));
        }

        return new Dtr2Fixture(
            new Dtr2Record(Bytes(16, 0x14), Bytes(32, 0x93), 2, 3, 5, 7, 11, 13, message),
            payload);
    }

    internal static Dpe2Record Dpe2(Dtr2Record header, int ciphertextLength) => new(
        header.NetworkId.Span,
        Bytes(32, 0x24),
        Bytes(32, 0x34),
        Bytes(32, 0x44),
        Bytes(32, 0x54),
        header,
        Dpe2Ciphertext.Import(Bytes(ciphertextLength, 0x64)));
}

internal sealed record Dtr2Fixture(Dtr2Record Record, byte[] Payload);

internal static class ManualMessagingWire
{
    internal static byte[] Record(string magic, params (ushort Tag, byte[] Value)[] fields)
    {
        var length = 12 + fields.Sum(static field => 8 + field.Value.Length);
        var output = new byte[length];
        Encoding.ASCII.GetBytes(magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4, 2), 1);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6, 2), 0x0201);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8, 2), checked((ushort)fields.Length));
        var offset = 12;
        foreach (var field in fields)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2), field.Tag);
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4, 4), checked((uint)field.Value.Length));
            field.Value.CopyTo(output, offset + 8);
            offset += 8 + field.Value.Length;
        }

        return output;
    }

    internal static (ushort Tag, byte[] Value)[] Dpk2Fields(Dpk2Record record) =>
    [
        (1, record.NetworkId.ToArray()),
        (2, record.ResponderAccountId.ToArray()),
        (3, record.ResponderDeviceId.ToArray()),
        (4, U64(record.ResponderDeviceGeneration)),
        (5, record.ResponderDpd1Ref.ToArray()),
        (6, U64(record.DeviceDirectoryGeneration)),
        (7, record.DeviceDirectoryHeadHash.ToArray()),
        (8, U64(record.PrekeyServiceGeneration)),
        (9, U64(record.InventoryEpoch)),
        (10, record.BundleId.ToArray()),
        (11, U64(record.PolicyGeneration)),
        (12, U64(record.NotBefore)),
        (13, U64(record.IssuedAt)),
        (14, U64(record.ExpiresAt)),
        (15, record.DeviceAgreementPublicKey.ToArray()),
        (16, record.SignedX25519PrekeyId.ToArray()),
        (17, record.SignedX25519PrekeyPublic.ToArray()),
        (18, record.SignedX25519PrekeySignature.ToArray()),
        (19, record.OneTimeX25519PrekeyId.ToArray()),
        (20, record.OneTimeX25519PrekeyPublic.ToArray()),
        (21, record.MlKemPrekeyId.ToArray()),
        (22, record.MlKem768EncapsulationKey.ToArray()),
        (23, [(byte)record.MlKemKind]),
        (24, U16(record.ReuseLimit)),
        (25, record.MlKemPrekeySignature.ToArray()),
        (26, record.BundleSignature.ToArray()),
    ];

    internal static (ushort Tag, byte[] Value)[] Dph2Fields(Dph2Record record)
    {
        var selected = Concat(
            record.SelectedPrekey.SignedX25519PrekeyId.ToArray(),
            record.SelectedPrekey.OneTimeX25519PrekeyIdOrZero.ToArray(),
            record.SelectedPrekey.MlKemPrekeyId.ToArray(),
            [(byte)record.SelectedPrekey.Kind]);
        var ciphertext = new byte[record.InitialCiphertext.Length];
        record.InitialCiphertext.CopyCiphertextTo(ciphertext);
        return
        [
            (1, record.NetworkId.ToArray()),
            (2, record.InitiatorAccountId.ToArray()),
            (3, record.InitiatorDeviceId.ToArray()),
            (4, U64(record.InitiatorDeviceGeneration)),
            (5, record.InitiatorDpd1Ref.ToArray()),
            (6, record.ResponderAccountId.ToArray()),
            (7, record.ResponderDeviceId.ToArray()),
            (8, U64(record.ResponderDeviceGeneration)),
            (9, record.ExactDpk2Hash.ToArray()),
            (10, record.ClaimOperationId.ToArray()),
            (11, record.ClaimReceiptHash.ToArray()),
            (12, U16(record.LastResortUseCounter)),
            (13, record.SessionId.ToArray()),
            (14, record.InitiatorDeviceAgreementPublicKey.ToArray()),
            (15, record.InitiatorEphemeralX25519PublicKey.ToArray()),
            (16, selected),
            (17, record.ActualMlKem768Ciphertext.ToArray()),
            (18, record.InitiatorInitialRatchetX25519PublicKey.ToArray()),
            (19, record.InitialPayloadNonce.ToArray()),
            (20, ciphertext),
        ];
    }

    internal static (ushort Tag, byte[] Value)[] Dtr2Fields(Dtr2Fixture fixture) =>
    [
        (1, fixture.Record.NetworkId.ToArray()),
        (2, fixture.Record.EcRatchetPublicKey.ToArray()),
        (3, U64(fixture.Record.EcPreviousSendingChainLength)),
        (4, U64(fixture.Record.EcMessageNumber)),
        (5, U64(fixture.Record.SckaSendingEpoch)),
        (6, U64(fixture.Record.SckaPreviousSendingChainLength)),
        (7, U64(fixture.Record.SckaMessageNumber)),
        (8, U64(fixture.Record.BraidEpoch)),
        (9, [(byte)fixture.Record.BraidMessage.Kind]),
        (10, fixture.Payload),
    ];

    internal static (ushort Tag, byte[] Value)[] Dpe2Fields(
        Dpe2Record record,
        byte[] manualDtr2)
    {
        var ciphertext = new byte[record.Ciphertext.Length];
        record.Ciphertext.CopyCiphertextTo(ciphertext);
        return
        [
            (1, record.NetworkId.ToArray()),
            (2, record.SessionId.ToArray()),
            (3, record.SenderDeviceId.ToArray()),
            (4, record.RecipientDeviceId.ToArray()),
            (5, record.OperationId.ToArray()),
            (6, manualDtr2),
            (7, ciphertext),
        ];
    }

    internal static byte[] SignatureInput(string label, byte[] record) =>
        Concat(Encoding.ASCII.GetBytes(label), [0], U16(0x0201), U32((uint)record.Length), record);

    internal static byte[] DomainInput(string label, byte[] value) =>
        Concat(Encoding.ASCII.GetBytes(label), [0], U32((uint)value.Length), value);

    internal static byte[] Sha256Domain(string label, byte[] value) =>
        SHA256.HashData(DomainInput(label, value));

    internal static byte[] Context(string label, params byte[][] parts)
    {
        var values = new List<byte[]>
        {
            Encoding.ASCII.GetBytes(label),
            new byte[] { 0 },
            U16(0x0201),
            U16((ushort)parts.Length),
        };
        foreach (var part in parts)
        {
            values.Add(U32((uint)part.Length));
            values.Add(part);
        }

        return Concat(values.ToArray());
    }

    internal static byte[] Lp32(byte[] value) => Concat(U32((uint)value.Length), value);

    internal static byte[] U16(ushort value)
    {
        var output = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(output, value);
        return output;
    }

    internal static byte[] U32(uint value)
    {
        var output = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(output, value);
        return output;
    }

    internal static byte[] U64(ulong value)
    {
        var output = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(output, value);
        return output;
    }

    internal static byte[] Concat(params byte[][] values)
    {
        var output = new byte[values.Sum(static value => value.Length)];
        var offset = 0;
        foreach (var value in values)
        {
            value.CopyTo(output, offset);
            offset += value.Length;
        }

        return output;
    }
}
