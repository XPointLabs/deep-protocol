#if DEEP_MLKEM_ANDROID_PROBE
namespace Deep.Protocol.MessagingCrypto;

/// <summary>
/// Fixed development evidence identity compiled only into the isolated Android
/// probe graph. It is deliberately absent from ordinary production builds and
/// does not confer release approval on the Android asset.
/// </summary>
internal static class DeepMlKemAndroidProbeApprovedAssets
{
    internal static DeepMlKemApprovedAsset AndroidArm64 { get; } = new(
        "android-arm64",
        "runtimes/android-arm64/native/libdeep_mlkem.so",
        325216,
        "7799b36b8c522905f655af518124cdd74b97224c4ee42beb2f8142065392cd87",
        DeepMlKemApprovedAssets.ManifestProviderIdentifier);

    internal static DeepMlKemApprovedAsset ForCurrentProcess()
    {
        if (OperatingSystem.IsAndroid() &&
            System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture ==
            System.Runtime.InteropServices.Architecture.Arm64)
            return AndroidArm64;

        throw new PlatformNotSupportedException(
            "The isolated Deep ML-KEM Android probe requires an Android arm64 process.");
    }
}
#endif
