using System.Windows;
using WinShield.Services;
using WinShield.Ui;
using WinShield.ViewModels;

namespace WinShield;

public partial class App : Application
{
    private ProtectionService? _protection;
    private ShellViewModel? _shell;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var ui = new WpfUiServices();

        // Anything a button handler throws becomes a message instead of a crash.
        RelayCommand.ErrorHandler = ex => ui.ShowMessage("WinShield", ex.Message);
        DispatcherUnhandledException += (_, args) =>
        {
            ui.ShowMessage("WinShield", "Something unexpected went wrong, but WinShield is still running:\n\n" + args.Exception.Message);
            args.Handled = true;
        };

        _protection = new ProtectionService();
        _shell = new ShellViewModel(_protection, ui);

        var window = new MainWindow(_shell);
        MainWindow = window;
        window.Show();

        await _shell.InitializeAsync();
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _shell?.Dispose();
        _protection?.Dispose();   // stops the watchers and releases anything WinShield suspended
        base.OnExit(e);
    }
}
