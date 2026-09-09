using Android.App;
using Android.OS;
using Android.Util;
using Android.Widget;

namespace Deep.MlKem.AndroidProbe;

[Activity(
    Label = "Deep ML-KEM Android Probe",
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
            Text = "Running bounded Deep ML-KEM native probe...",
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
        var json = await Task.Run(() => ProbeRunner.Run(Assets)).ConfigureAwait(false);
        _ = Log.Info("DeepMlKemProbe", json);
        RunOnUiThread(() =>
        {
            if (_resultView is not null)
                _resultView.Text = json;
        });
    }
}
