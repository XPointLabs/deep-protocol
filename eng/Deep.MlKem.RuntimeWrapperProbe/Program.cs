using System.Reflection;
using System.Runtime.InteropServices;

if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture is not
        (Architecture.X64 or Architecture.Arm64))
    throw new PlatformNotSupportedException("This evidence probe requires a Windows x64 or arm64 process.");
if (args.Length != 2)
    throw new ArgumentException("Expected the Deep.Protocol.Tests assembly and reviewed native asset paths.");

var testAssemblyPath = Path.GetFullPath(args[0]);
var nativeAssetPath = Path.GetFullPath(args[1]);
if (!File.Exists(testAssemblyPath) || !File.Exists(nativeAssetPath))
    throw new FileNotFoundException("The wrapper probe input is absent.");

Environment.SetEnvironmentVariable("DEEP_MLKEM_TEST_ASSET", nativeAssetPath);
try
{
    var assembly = Assembly.LoadFrom(testAssemblyPath);
    var type = assembly.GetType(
        "Deep.Protocol.Tests.MessagingCrypto.DeepMlKemNativeProviderTests",
        throwOnError: true)!;
    var instance = Activator.CreateInstance(type)!;
    var methods = type.GetMethods(BindingFlags.Public | BindingFlags.Instance)
        .Where(static method => method.Name.StartsWith("Windows_", StringComparison.Ordinal))
        .OrderBy(static method => method.Name, StringComparer.Ordinal)
        .ToArray();
    if (methods.Length != 3)
        throw new InvalidOperationException("Expected exactly three Windows production-wrapper tests.");
    foreach (var method in methods)
    {
        try
        {
            var result = method.Invoke(instance, null);
            if (result is Task task) await task;
            Console.WriteLine($"PASS {method.Name}");
        }
        catch (TargetInvocationException exception)
        {
            throw exception.InnerException ?? exception;
        }
    }
}
finally
{
    Environment.SetEnvironmentVariable("DEEP_MLKEM_TEST_ASSET", null);
}
