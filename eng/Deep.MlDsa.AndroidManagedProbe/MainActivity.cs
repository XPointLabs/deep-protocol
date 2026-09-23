using Android.App;
using Android.OS;
using Android.Util;
using Android.Widget;

namespace Deep.MlDsa.AndroidManagedProbe;

[Activity(Label = "Deep ML-DSA Candidate Probe", MainLauncher = true, Exported = true)]
public sealed class MainActivity : Activity
{
    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        var report = ProbeRunner.Run(Assets);
        Log.Info("DEEP_MLDSA_PROBE", report);
        SetContentView(new TextView(this) { Text = report });
    }
}
