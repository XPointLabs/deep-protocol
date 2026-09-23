using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Android.Content.Res;

namespace Deep.MlDsa.AndroidManagedProbe;

internal readonly record struct AcvpResult(int KeyGen, int SigGen, int SigVer, int Positive, int Negative);

internal static class AcvpRunner
{
    // Official usnistgov/ACVP-Server v1.1.0.43 files, SHA-256-pinned before parsing.
    private static readonly (string Name, string Digest)[] Files =
    [
        ("keygen-prompt.json", "43e81ad820e495dbcad086fe27c1008393a8c32100bbbff77c558c3f06dcefef"),
        ("keygen-expected.json", "361f47ca19d592adcc66ff2cb591686ad785fea157b295648738bed6921a68df"),
        ("siggen-prompt.json", "0a81a213fb4825f0a9d8893a20445a3fed88a6f1832703548120b9588c74a08e"),
        ("siggen-expected.json", "8d86d120d128d2f2d29afb7843b7351677ac0f1bf649295d85b7bf3dd533949c"),
        ("sigver-prompt.json", "e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e"),
        ("sigver-expected.json", "e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6")
    ];

    internal static AcvpResult Run(AssetManager assets, nint handle)
    {
        var derive = Bind<PublicFromSeedFunction>(handle, "deep_mldsa_v1_public_from_seed");
        var sign = Bind<SignFromSeedFunction>(handle, "deep_mldsa_v1_sign_from_seed");
        var verify = Bind<VerifyFunction>(handle, "deep_mldsa_v1_verify");
        using var keygenPrompt = Open(assets, Files[0]);
        using var keygenExpected = Open(assets, Files[1]);
        var keygen = KeyGen(keygenPrompt.RootElement, keygenExpected.RootElement, derive);
        using var siggenPrompt = Open(assets, Files[2]);
        using var siggenExpected = Open(assets, Files[3]);
        var siggen = SigGen(siggenPrompt.RootElement, siggenExpected.RootElement, sign);
        using var sigverPrompt = Open(assets, Files[4]);
        using var sigverExpected = Open(assets, Files[5]);
        var (sigver, positive, negative) = SigVer(
            sigverPrompt.RootElement, sigverExpected.RootElement, verify);
        if (keygen != 25 || siggen != 30 || sigver != 15 || positive != 3 || negative != 12)
            throw new CryptographicException("ACVP coverage changed.");
        return new AcvpResult(keygen, siggen, sigver, positive, negative);
    }

    private static JsonDocument Open(AssetManager assets, (string Name, string Digest) file)
    {
        var name = "acvp/" + file.Name;
        using (var hashSource = assets.Open(name, Access.Streaming))
        {
            var hash = Convert.ToHexString(SHA256.HashData(hashSource)).ToLowerInvariant();
            if (!StringComparer.Ordinal.Equals(hash, file.Digest))
                throw new CryptographicException("Packaged official ACVP vector digest mismatch.");
        }
        using var jsonSource = assets.Open(name, Access.Streaming);
        return JsonDocument.Parse(jsonSource);
    }

    private static IEnumerable<JsonElement> Groups(JsonElement prompt)
    {
        if (prompt.GetProperty("algorithm").GetString() != "ML-DSA")
            throw new CryptographicException("Unexpected ACVP algorithm.");
        return prompt.GetProperty("testGroups").EnumerateArray()
            .Where(static group => group.GetProperty("parameterSet").GetString() == "ML-DSA-65");
    }

    private static Dictionary<int, JsonElement> Expected(JsonElement expected, int groupId)
    {
        var groups = expected.GetProperty("testGroups").EnumerateArray()
            .Where(group => group.GetProperty("tgId").GetInt32() == groupId).ToArray();
        if (groups.Length != 1) throw new CryptographicException("Missing ACVP expected group.");
        return groups[0].GetProperty("tests").EnumerateArray()
            .ToDictionary(static item => item.GetProperty("tcId").GetInt32());
    }

    private static int KeyGen(JsonElement prompt, JsonElement expected, PublicFromSeedFunction derive)
    {
        var count = 0;
        foreach (var group in Groups(prompt))
        {
            if (group.GetProperty("testType").GetString() != "AFT")
                throw new CryptographicException("Unexpected keyGen test type.");
            var cases = Expected(expected, group.GetProperty("tgId").GetInt32());
            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                var seed = Hex(test, "seed");
                var reference = Hex(cases[test.GetProperty("tcId").GetInt32()], "pk");
                var actual = new byte[1952];
                try
                {
                    if (seed.Length != 32 || reference.Length != 1952)
                        throw new CryptographicException("Unexpected keyGen vector size.");
                    unsafe
                    {
                        fixed (byte* seedPtr = seed, actualPtr = actual)
                        {
                            if (derive(seedPtr, 32, actualPtr, 1952) != 0)
                                throw new CryptographicException("Native keyGen failed.");
                        }
                    }
                    if (!CryptographicOperations.FixedTimeEquals(actual, reference))
                        throw new CryptographicException("ACVP keyGen mismatch.");
                    count++;
                }
                finally { Zero(seed, reference, actual); }
            }
        }
        return count;
    }

    private static int SigGen(JsonElement prompt, JsonElement expected, SignFromSeedFunction sign)
    {
        var count = 0;
        var deterministic = 0;
        var randomized = 0;
        foreach (var group in Groups(prompt))
        {
            if (!IsPureExternal(group) || !HasValue(group, "keyFormat", "seed")) continue;
            var isDeterministic = group.GetProperty("deterministic").GetBoolean();
            var cases = Expected(expected, group.GetProperty("tgId").GetInt32());
            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                var seed = Hex(test, "seed");
                var random = isDeterministic ? new byte[32] : Hex(test, "rnd");
                var contextValue = Hex(test, "context");
                var messageValue = Hex(test, "message");
                var context = NonEmpty(contextValue);
                var message = NonEmpty(messageValue);
                var reference = Hex(cases[test.GetProperty("tcId").GetInt32()], "signature");
                var actual = new byte[3309];
                try
                {
                    if (seed.Length != 32 || random.Length != 32 ||
                        contextValue.Length > 255 || messageValue.Length > 65535 ||
                        reference.Length != 3309)
                        throw new CryptographicException("ACVP sigGen vector is outside Deep ABI.");
                    unsafe
                    {
                        fixed (byte* seedPtr = seed, randomPtr = random,
                               contextPtr = context, messagePtr = message, signaturePtr = actual)
                        {
                            if (sign(seedPtr, 32, randomPtr, 32, contextPtr,
                                    (nuint)contextValue.Length, messagePtr,
                                    (nuint)messageValue.Length, signaturePtr, 3309) != 0)
                                throw new CryptographicException("Native sigGen failed.");
                        }
                    }
                    if (!CryptographicOperations.FixedTimeEquals(actual, reference))
                        throw new CryptographicException("ACVP sigGen mismatch.");
                    count++;
                    if (isDeterministic) deterministic++; else randomized++;
                }
                finally { Zero(seed, random, contextValue, messageValue, context, message, reference, actual); }
            }
        }
        if (deterministic != 15 || randomized != 15)
            throw new CryptographicException("ACVP sigGen group coverage changed.");
        return count;
    }

    private static int SigVer(JsonElement prompt, JsonElement expected, VerifyFunction verify,
        out int positive, out int negative)
    {
        positive = negative = 0;
        var count = 0;
        foreach (var group in Groups(prompt))
        {
            if (!IsPureExternal(group)) continue;
            var cases = Expected(expected, group.GetProperty("tgId").GetInt32());
            foreach (var test in group.GetProperty("tests").EnumerateArray())
            {
                var publicKey = Hex(test, "pk");
                var contextValue = Hex(test, "context");
                var messageValue = Hex(test, "message");
                var signature = Hex(test, "signature");
                var context = NonEmpty(contextValue);
                var message = NonEmpty(messageValue);
                try
                {
                    if (publicKey.Length != 1952 || signature.Length != 3309 ||
                        contextValue.Length > 255 || messageValue.Length > 65535)
                        throw new CryptographicException("ACVP sigVer vector is outside Deep ABI.");
                    int result;
                    unsafe
                    {
                        fixed (byte* publicPtr = publicKey, contextPtr = context,
                               messagePtr = message, signaturePtr = signature)
                        {
                            result = verify(publicPtr, 1952, contextPtr,
                                (nuint)contextValue.Length, messagePtr,
                                (nuint)messageValue.Length, signaturePtr, 3309);
                        }
                    }
                    var shouldPass = cases[test.GetProperty("tcId").GetInt32()]
                        .GetProperty("testPassed").GetBoolean();
                    if (result != (shouldPass ? 0 : 4))
                        throw new CryptographicException("ACVP sigVer mismatch.");
                    count++;
                    if (shouldPass) positive++; else negative++;
                }
                finally { Zero(publicKey, contextValue, messageValue, signature, context, message); }
            }
        }
        return count;
    }

    private static (int Count, int Positive, int Negative) SigVer(
        JsonElement prompt, JsonElement expected, VerifyFunction verify)
    {
        var count = SigVer(prompt, expected, verify, out var positive, out var negative);
        return (count, positive, negative);
    }

    private static bool IsPureExternal(JsonElement group) =>
        HasValue(group, "testType", "AFT") &&
        HasValue(group, "signatureInterface", "external") &&
        HasValue(group, "preHash", "pure");

    private static bool HasValue(JsonElement item, string name, string expected) =>
        item.TryGetProperty(name, out var value) && value.GetString() == expected;

    private static byte[] Hex(JsonElement item, string name) =>
        Convert.FromHexString(item.GetProperty(name).GetString()
            ?? throw new CryptographicException("ACVP hex value is null."));

    private static byte[] NonEmpty(byte[] bytes) => bytes.Length == 0 ? new byte[1] : bytes;

    private static void Zero(params byte[][] arrays)
    {
        foreach (var array in arrays) CryptographicOperations.ZeroMemory(array);
    }

    private static T Bind<T>(nint handle, string name) where T : Delegate =>
        Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(handle, name));

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int PublicFromSeedFunction(
        byte* seed, nuint seedLength, byte* publicKey, nuint publicLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int SignFromSeedFunction(
        byte* seed, nuint seedLength, byte* random, nuint randomLength,
        byte* context, nuint contextLength, byte* message, nuint messageLength,
        byte* signature, nuint signatureLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private unsafe delegate int VerifyFunction(
        byte* publicKey, nuint publicLength, byte* context, nuint contextLength,
        byte* message, nuint messageLength, byte* signature, nuint signatureLength);
}
