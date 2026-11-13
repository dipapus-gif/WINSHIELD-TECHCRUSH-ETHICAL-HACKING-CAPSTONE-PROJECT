using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
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
            ui.ShowMessage("WinShield", "Something unexpected went wrong, but WinShield is still running:\n\n" + Describe(args.Exception));
            args.Handled = true;
        };

        Ui.ThemeManager.Init();   // before any window exists, so every brush is defined

        // Build check used by CI: opens every screen in both themes, saves screenshots, reports any exception.
        var testIdx = Array.IndexOf(e.Args, "--ui-selftest");
        if (testIdx >= 0)
        {
            await RunUiSelfTest(testIdx + 1 < e.Args.Length ? e.Args[testIdx + 1] : "ui-shots");
            return;
        }

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

    /// <summary>Message plus every inner exception, so a failure says where it really happened.</summary>
    private static string Describe(Exception ex)
    {
        var sb = new StringBuilder();
        for (var cur = ex; cur != null; cur = cur.InnerException)
        {
            if (sb.Length > 0) sb.Append("\n  caused by: ");
            sb.Append(cur.Message);
        }
        return sb.ToString();
    }

    private static void Flush()
    {
        Current.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
        Current.Dispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
    }

    private static void Snap(Window w, string file)
    {
        w.UpdateLayout();
        var el = (FrameworkElement)w.Content;
        int width = (int)Math.Max(1, el.ActualWidth), height = (int)Math.Max(1, el.ActualHeight);
        var bmp = new RenderTargetBitmap(width, height, 96, 96, PixelFormats.Pbgra32);
        bmp.Render(el);
        var enc = new PngBitmapEncoder();
        enc.Frames.Add(BitmapFrame.Create(bmp));
        using var fs = File.Create(file);
        enc.Save(fs);
    }

    private async Task RunUiSelfTest(string outDir)
    {
        var log = new StringBuilder();
        var failed = false;
        try
        {
            Directory.CreateDirectory(outDir);
            var ui = new WpfUiServices();
            _protection = new ProtectionService();
            _shell = new ShellViewModel(_protection, ui);

            try { await _shell.InitializeAsync(); log.AppendLine("shell initialised (database schema loaded)"); }
            catch (Exception ex) { failed = true; log.AppendLine("INIT FAILED: " + ex); }

            foreach (var dark in new[] { true, false })
            {
                var name = dark ? "dark" : "light";
                try
                {
                    Ui.ThemeManager.Apply(dark);

                    var login = new LoginWindow(new AccountStore(Path.Combine(outDir, "accounts-" + name + ".json")));
                    login.Show(); Flush();
                    Snap(login, Path.Combine(outDir, $"login-{name}.png"));
                    login.Close();

                    var win = new MainWindow(_shell, "tester") { Width = 1300, Height = 860 };
                    win.Show(); Flush();
                    var tabs = FindTabControl(win);
                    var count = tabs?.Items.Count ?? 0;
                    for (int i = 0; i < count; i++)
                    {
                        tabs!.SelectedIndex = i; Flush();
                        Snap(win, Path.Combine(outDir, $"console-{name}-tab{i}.png"));
                    }
                    log.AppendLine($"{name}: login + console with {count} tabs rendered");
                    win.Close();
                }
                catch (Exception ex) { failed = true; log.AppendLine($"{name} FAILED:\n{ex}"); }
            }
        }
        catch (Exception ex) { failed = true; log.AppendLine("SELF-TEST FAILED: " + ex); }

        try { File.WriteAllText(Path.Combine(outDir, "selftest.log"), log.ToString()); } catch { }
        Shutdown(failed ? 1 : 0);
    }

    private static TabControl? FindTabControl(DependencyObject root)
    {
        foreach (var child in LogicalTreeHelper.GetChildren(root).OfType<DependencyObject>())
        {
            if (child is TabControl t) return t;
            var found = FindTabControl(child);
            if (found != null) return found;
        }
        return null;
    }
}
