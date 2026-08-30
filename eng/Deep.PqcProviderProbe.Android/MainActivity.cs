using Android.App;
using Android.OS;
using Android.Util;
using Android.Widget;

namespace Deep.PqcProviderProbe.Android;

[Activity(
    Label = "Deep PQC Provider Probe",
    MainLauncher = true,
    Exported = true)]
public sealed class MainActivity : Activity
{
    private TextView? _resultView;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);

        _resultView = new TextView(this)
        {
            Text = "Running bounded ML-KEM-768 provider probe...",
            TextSize = 12
        };
        _resultView.SetPadding(24, 24, 24, 24);
        _resultView.SetTextIsSelectable(true);

        var scroll = new ScrollView(this);
        scroll.AddView(_resultView);
        SetContentView(scroll);

        _ = DisplayResultAsync();
    }

    private async Task DisplayResultAsync()
    {
        var json = await ProbeExecution.Result.ConfigureAwait(false);
        RunOnUiThread(() =>
        {
            if (_resultView is not null)
                _resultView.Text = json;
        });
    }
}

internal static class ProbeExecution
{
    private const string LogTag = "DeepPqcProbe";

    internal static Task<string> Result { get; } = Task.Run(() =>
    {
        var json = ProbeRunner.Run();
        _ = Log.Info(LogTag, json);
        return json;
    });
}
