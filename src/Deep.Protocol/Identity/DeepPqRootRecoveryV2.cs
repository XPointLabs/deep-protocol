using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Protocol.Identity;

internal delegate void DeepPqRootMaterialConsumer(
    ReadOnlySpan<byte> ed25519Seed,
    ReadOnlySpan<byte> mlDsa65Seed,
    ReadOnlySpan<byte> resolverReadCapability);

// This derives the genesis root only. A separate frozen DID2/DAB2 codec must
// bind the resulting public keys before this material can create an account.
internal static class DeepPqRootRecoveryV2
{
    private const string Context = "DeepGlobalPqRootV2";
    private const int Bip39Rounds = 2048;

    internal static void UseRootMaterial(
        VerifiedDeepRecoveryPhrase phrase,
        DeepPqRootMaterialConsumer consumer)
    {
        ArgumentNullException.ThrowIfNull(phrase);
        ArgumentNullException.ThrowIfNull(consumer);

        byte[]? mnemonic = null;
        byte[]? bip39Seed = null;
        byte[]? extractSalt = null;
        byte[]? prk = null;
        byte[]? edSeed = null;
        byte[]? pqSeed = null;
        byte[]? readCapability = null;
        try
        {
            phrase.UseCanonicalUtf8(bytes => mnemonic = bytes.ToArray());
            if (mnemonic is null)
                throw new CryptographicException("Recovery phrase export did not complete.");

            bip39Seed = Rfc2898DeriveBytes.Pbkdf2(
                mnemonic,
                "mnemonic"u8,
                Bip39Rounds,
                HashAlgorithmName.SHA512,
                64);
            extractSalt = SHA512.HashData("Deep/Recovery/V2/PQ-root/extract"u8);
            prk = new byte[SHA512.HashSizeInBytes];
            if (HKDF.Extract(HashAlgorithmName.SHA512, bip39Seed, extractSalt, prk) != prk.Length)
                throw new CryptographicException("HKDF extract returned an unexpected length.");

            edSeed = Expand(prk, "Deep/Recovery/V2/root-ed25519-signing-seed", 32);
            pqSeed = Expand(prk, "Deep/Recovery/V2/root-mldsa65-signing-seed", 32);
            readCapability = Expand(prk, "Deep/Recovery/V2/root-resolver-read-capability", 16);
            consumer(edSeed, pqSeed, readCapability);
        }
        finally
        {
            Zero(mnemonic);
            Zero(bip39Seed);
            Zero(extractSalt);
            Zero(prk);
            Zero(edSeed);
            Zero(pqSeed);
            Zero(readCapability);
        }
    }

    private static byte[] Expand(ReadOnlySpan<byte> prk, string label, int outputLength)
    {
        var labelBytes = Encoding.ASCII.GetBytes(label);
        var contextBytes = Encoding.ASCII.GetBytes(Context);
        var info = new byte[labelBytes.Length + 1 + sizeof(uint) + contextBytes.Length];
        try
        {
            labelBytes.CopyTo(info, 0);
            BinaryPrimitives.WriteUInt32BigEndian(
                info.AsSpan(labelBytes.Length + 1), checked((uint)contextBytes.Length));
            contextBytes.CopyTo(info.AsSpan(labelBytes.Length + 1 + sizeof(uint)));
            var output = new byte[outputLength];
            try
            {
                HKDF.Expand(HashAlgorithmName.SHA512, prk, output, info);
                return output;
            }
            catch
            {
                Zero(output);
                throw;
            }
        }
        finally
        {
            Zero(labelBytes);
            Zero(contextBytes);
            Zero(info);
        }
    }

    private static void Zero(byte[]? value)
    {
        if (value is not null)
            CryptographicOperations.ZeroMemory(value);
    }
}
