using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

// Test-only provider feasibility. Never persist or print seed/private-key bytes.
const string ExpectedTestVectorPublicKeySha256 =
    "d666806e11cee19a7c989f7445f90dd419cf4d2d51db8c0fdb4c0f0a542238c9";
var parameters = MLDsaParameters.ml_dsa_65;
var seed = RandomNumberGenerator.GetBytes(32);
var message = Encoding.ASCII.GetBytes("Deep/PQRoot/provider-probe/v1");
byte[]? publicKeyBytes = null;
byte[]? restoredPublicKeyBytes = null;
byte[]? signature = null;
byte[]? testVectorSeed = null;
byte[]? testVectorPublicKey = null;
try
{
    var privateKey = MLDsaPrivateKeyParameters.FromSeed(parameters, seed);
    var restored = MLDsaPrivateKeyParameters.FromSeed(parameters, seed.ToArray());
    publicKeyBytes = privateKey.GetPublicKeyEncoded();
    restoredPublicKeyBytes = restored.GetPublicKeyEncoded();
    var deterministicRecovery = CryptographicOperations.FixedTimeEquals(
        publicKeyBytes, restoredPublicKeyBytes);

    var signer = new MLDsaSigner(parameters, deterministic: true);
    signer.Init(true, privateKey);
    signer.BlockUpdate(message, 0, message.Length);
    signature = signer.GenerateSignature();

    var importedPublic = MLDsaPublicKeyParameters.FromEncoding(parameters, publicKeyBytes);
    var verifier = new MLDsaSigner(parameters, deterministic: true);
    verifier.Init(false, importedPublic);
    verifier.BlockUpdate(message, 0, message.Length);
    var signatureVerified = verifier.VerifySignature(signature);

    message[0] ^= 1;
    verifier.BlockUpdate(message, 0, message.Length);
    var tamperedMessageRejected = !verifier.VerifySignature(signature);

    var replacementSeed = RandomNumberGenerator.GetBytes(32);
    bool substitutedKeyRejected;
    try
    {
        var replacement = MLDsaPrivateKeyParameters.FromSeed(parameters, replacementSeed);
        var replacementPublic = MLDsaPublicKeyParameters.FromEncoding(
            parameters, replacement.GetPublicKeyEncoded());
        verifier.Init(false, replacementPublic);
        message[0] ^= 1;
        verifier.BlockUpdate(message, 0, message.Length);
        substitutedKeyRejected = !verifier.VerifySignature(signature);
    }
    finally
    {
        CryptographicOperations.ZeroMemory(replacementSeed);
    }

    var privateKeyType = typeof(MLDsaPrivateKeyParameters);
    var disposable = typeof(IDisposable).IsAssignableFrom(privateKeyType);
    var secretArrays = privateKeyType.GetFields(BindingFlags.Instance | BindingFlags.NonPublic)
        .Count(field => field.FieldType == typeof(byte[]));
    // Public interoperability fixture only. The seed is fixed and never an account secret.
    testVectorSeed = Enumerable.Range(0, 32).Select(static value => (byte)value).ToArray();
    testVectorPublicKey = MLDsaPrivateKeyParameters.FromSeed(parameters, testVectorSeed)
        .GetPublicKeyEncoded();
    var testVectorPublicKeySha256 = Convert.ToHexString(SHA256.HashData(testVectorPublicKey))
        .ToLowerInvariant();
    var testVectorMatched = StringComparer.Ordinal.Equals(
        testVectorPublicKeySha256, ExpectedTestVectorPublicKeySha256);
    var success = deterministicRecovery && signatureVerified &&
        tamperedMessageRejected && substitutedKeyRejected && testVectorMatched;
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        schemaVersion = "1",
        provider = "BouncyCastle.Cryptography/2.7.0",
        algorithm = "ML-DSA-65",
        runtime = RuntimeInformation.RuntimeIdentifier,
        success,
        productionEligible = false,
        blockers = new[] { "upstream_experimental", "private_key_lifecycle_unreviewed" },
        deterministicRecovery,
        signatureVerified,
        tamperedMessageRejected,
        substitutedKeyRejected,
        publicKeyBytes = publicKeyBytes.Length,
        signatureBytes = signature.Length,
        privateKeyImplementsIDisposable = disposable,
        privateKeyOwnedByteArrayFields = secretArrays,
        testVectorPublicKeySha256,
        testVectorMatched,
    }));
    return success ? 0 : 1;
}
finally
{
    CryptographicOperations.ZeroMemory(seed);
    CryptographicOperations.ZeroMemory(message);
    if (publicKeyBytes is not null) CryptographicOperations.ZeroMemory(publicKeyBytes);
    if (restoredPublicKeyBytes is not null) CryptographicOperations.ZeroMemory(restoredPublicKeyBytes);
    if (signature is not null) CryptographicOperations.ZeroMemory(signature);
    if (testVectorSeed is not null) CryptographicOperations.ZeroMemory(testVectorSeed);
    if (testVectorPublicKey is not null) CryptographicOperations.ZeroMemory(testVectorPublicKey);
}
