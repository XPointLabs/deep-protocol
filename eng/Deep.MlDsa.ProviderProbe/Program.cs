using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

// Test-only provider feasibility. Never persist or print seed/private-key bytes.
var parameters = MLDsaParameters.ml_dsa_65;
var seed = RandomNumberGenerator.GetBytes(32);
var message = Encoding.ASCII.GetBytes("Deep/PQRoot/provider-probe/v1");
byte[]? publicKeyBytes = null;
byte[]? restoredPublicKeyBytes = null;
byte[]? signature = null;
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
    var success = deterministicRecovery && signatureVerified &&
        tamperedMessageRejected && substitutedKeyRejected;
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
}
