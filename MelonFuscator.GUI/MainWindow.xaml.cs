using System;
using System.IO;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using MelonFuscator.Engine;

namespace MelonFuscator.GUI;

public partial class MainWindow : Window
{
    private bool _busy;

    public MainWindow()
    {
        InitializeComponent();
    }

    private CheckBox[] AllChecks() => new[]
    {
        chkRename, chkStrings, chkConstants, chkMutate, chkEncode, chkProxy, chkFlatten, chkFlow,
        chkAntiDebug, chkAntiTamper, chkAntiDecompiler, chkBomb
    };

    private void All_Click(object sender, RoutedEventArgs e)
    {
        foreach (var c in AllChecks()) c.IsChecked = true;
    }

    private void None_Click(object sender, RoutedEventArgs e)
    {
        foreach (var c in AllChecks()) c.IsChecked = false;
    }

    private void Open_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select the mod assembly to obfuscate",
            Filter = ".NET assemblies (*.dll)|*.dll|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() == true)
        {
            txtInput.Text = dlg.FileName;
            if (string.IsNullOrWhiteSpace(txtOutput.Text))
                txtOutput.Text = SuggestOutput(dlg.FileName);
        }
    }

    private void Export_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title = "Save the obfuscated assembly as",
            Filter = ".NET assemblies (*.dll)|*.dll",
            FileName = string.IsNullOrWhiteSpace(txtInput.Text)
                ? "MyMod.obf.dll"
                : Path.GetFileName(SuggestOutput(txtInput.Text))
        };
        if (dlg.ShowDialog() == true)
            txtOutput.Text = dlg.FileName;
    }

    private static string SuggestOutput(string input)
    {
        var dir = Path.GetDirectoryName(Path.GetFullPath(input)) ?? "";
        var name = Path.GetFileNameWithoutExtension(input);
        return Path.Combine(dir, name + ".obf.dll");
    }

    private async void Obfuscate_Click(object sender, RoutedEventArgs e)
    {
        if (_busy) return;

        var input = txtInput.Text.Trim();
        if (string.IsNullOrWhiteSpace(input) || !File.Exists(input))
        {
            SetStatus("Pick a valid input .dll first.", isError: true);
            return;
        }
        var output = txtOutput.Text.Trim();
        if (string.IsNullOrWhiteSpace(output))
        {
            output = SuggestOutput(input);
            txtOutput.Text = output;
        }

        var options = new ObfuscationOptions
        {
            InputPath = input,
            OutputPath = output,
            MelonLoaderFriendly = true,
            SelfVerify = true,
            Rename = chkRename.IsChecked == true,
            EncryptStrings = chkStrings.IsChecked == true,
            EncryptConstants = chkConstants.IsChecked == true,
            Mutate = chkMutate.IsChecked == true,
            EncodeLocals = chkEncode.IsChecked == true,
            ProxyCalls = chkProxy.IsChecked == true,
            Flatten = chkFlatten.IsChecked == true,
            ControlFlow = chkFlow.IsChecked == true,
            AntiDebug = chkAntiDebug.IsChecked == true,
            AntiTamper = chkAntiTamper.IsChecked == true,
            AntiDecompiler = chkAntiDecompiler.IsChecked == true,
            DecompilerBomb = chkBomb.IsChecked == true,
        };

        SetBusy(true);
        txtLog.Clear();
        SetStatus("Obfuscating...", isError: false);

        var log = new Logger
        {
            Sink = (level, text) => Dispatcher.Invoke(() => AppendLog(text))
        };

        bool ok = false;
        try
        {
            ok = await Task.Run(() => new ObfuscationEngine(log).Run(options));
        }
        catch (Exception ex)
        {
            Dispatcher.Invoke(() => AppendLog("[-] " + ex.Message));
        }

        if (ok)
            SetStatus("Done — MelonLoader-friendly output written.", isError: false, success: true);
        else
            SetStatus("Failed — see the log below.", isError: true);

        SetBusy(false);
    }

    private void AppendLog(string line)
    {
        txtLog.AppendText(line + "\n");
        logScroller.ScrollToEnd();
    }

    private void SetStatus(string text, bool isError, bool success = false)
    {
        txtStatus.Text = text;
        txtStatus.Foreground = success
            ? (Brush)FindResource("Accent")
            : isError ? (Brush)FindResource("DangerText") : (Brush)FindResource("TextSecond");
    }

    private void SetBusy(bool busy)
    {
        _busy = busy;
        btnObfuscate.IsEnabled = !busy;
        btnObfuscate.Content = busy ? "Obfuscating…" : "Obfuscate";
        btnOpen.IsEnabled = !busy;
        btnExport.IsEnabled = !busy;
    }
}
