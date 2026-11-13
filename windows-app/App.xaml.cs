using System.Windows;
using WinShield.Core;
using WinShield.Services;
using WinShield.Ui;
using WinShield.ViewModels;

namespace WinShield;

public partial class App : Application
{
    private ProtectionService? _protection;
    private ShellViewModel? _shell;
    private AccountStore? _accounts;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // The window closes on sign-out; only an explicit Shutdown() ends the app.
        ShutdownMode = ShutdownMode.OnExplicitShutdown;

        var ui = new WpfUiServices();

        // Anything a button handler throws becomes a message instead of a crash.
        RelayCommand.ErrorHandler = ex => ui.ShowMessage("WinShield", ex.Message);
        DispatcherUnhandledException += (_, args) =>
        {
            ui.ShowMessage("WinShield", "Something unexpected went wrong, but WinShield is still running:\n\n" + args.Exception.Message);
            args.Handled = true;
        };

        Ui.ThemeManager.Init();   // before any window exists, so every brush is defined

        _protection = new ProtectionService();
        _shell = new ShellViewModel(_protection, ui);

        _accounts = new AccountStore();
        if (!ShowMainWindow()) { Shutdown(); return; }

        await _shell.InitializeAsync();
    }

    /// <summary>Shows the sign-in window, then the console. Returns false when the user cancels sign-in.</summary>
    private bool ShowMainWindow()
    {
        var login = new LoginWindow(_accounts!);
        if (login.ShowDialog() != true || login.SignedInUser is null) return false;

        var window = new MainWindow(_shell!, login.SignedInUser);
        MainWindow = window;
        window.SignOutRequested += (_, _) =>
        {
            window.Closed -= OnConsoleClosed;
            window.Close();
            // Protection keeps running while signed out; only the console is locked.
            if (!ShowMainWindow()) Shutdown();
        };
        window.Closed += OnConsoleClosed;
        window.Show();
        return true;
    }

    private void OnConsoleClosed(object? sender, EventArgs e) => Shutdown();

    protected override void OnExit(ExitEventArgs e)
    {
        _shell?.Dispose();
        _protection?.Dispose();   // stops the watchers and releases anything WinShield suspended
        base.OnExit(e);
    }
}
