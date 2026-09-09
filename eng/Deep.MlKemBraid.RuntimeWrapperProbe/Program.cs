using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;

if (!OperatingSystem.IsWindows() ||
    RuntimeInformation.ProcessArchitecture is not (Architecture.X64 or Architecture.Arm64))
    throw new PlatformNotSupportedException("This evidence probe requires a Windows x64 or ARM64 process.");
if (args.Length != 3)
    throw new ArgumentException(
        "Expected the Deep.Protocol.Tests assembly, standard ML-KEM asset, and incremental Braid asset paths.");

var testAssemblyPath = Path.GetFullPath(args[0]);
var standardAssetPath = Path.GetFullPath(args[1]);
var braidAssetPath = Path.GetFullPath(args[2]);
if (!File.Exists(testAssemblyPath) || !File.Exists(standardAssetPath) || !File.Exists(braidAssetPath))
    throw new FileNotFoundException("A wrapper probe input is absent.");

Environment.SetEnvironmentVariable("DEEP_MLKEM_TEST_ASSET", standardAssetPath);
Environment.SetEnvironmentVariable("DEEP_MLKEM_BRAID_TEST_ASSET", braidAssetPath);
try
{
    var assembly = Assembly.LoadFrom(testAssemblyPath);
    var type = assembly.GetType(
        "Deep.Protocol.Tests.MessagingCrypto.DeepMlKemBraidNativeProviderTests",
        throwOnError: true)!;
    var instance = Activator.CreateInstance(type)!;
    var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
        .Where(static method => method.Name.StartsWith(
            "WindowsCurrentArchitecture_", StringComparison.Ordinal))
        .OrderBy(static method => method.Name, StringComparer.Ordinal)
        .ToArray();
    if (methods.Length != 3)
        throw new InvalidOperationException("Expected exactly three Windows Braid wrapper tests.");

    foreach (var method in methods)
    {
        try
        {
            var result = method.Invoke(instance, null);
            if (result is Task task) await task;
            Console.WriteLine($"PASS {method.Name}");
        }
        catch (TargetInvocationException exception) when (exception.InnerException is not null)
        {
            ExceptionDispatchInfo.Capture(exception.InnerException).Throw();
            throw;
        }
    }
}
finally
{
    Environment.SetEnvironmentVariable("DEEP_MLKEM_TEST_ASSET", null);
    Environment.SetEnvironmentVariable("DEEP_MLKEM_BRAID_TEST_ASSET", null);
}
