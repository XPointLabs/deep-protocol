using Android.App;
using Android.OS;
using Android.Util;
using Android.Widget;

namespace Deep.MlKemBraid.AndroidManagedProbe;

[Activity(
    Label = "Deep ML-KEM Braid Probe",
    MainLauncher = true,
    Exported = true)]
public sealed class MainActivity : Activity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        var report = ProbeRunner.Run(Assets);
        Log.Info("DEEP_MLKEM_BRAID_PROBE", report);
        SetContentView(new TextView(this) { Text = report });
    }
}
