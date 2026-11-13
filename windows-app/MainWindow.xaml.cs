using System.Windows;
using System.Windows.Input;
using WinShield.Ui;
using WinShield.ViewModels;

namespace WinShield;

public partial class MainWindow : Window
{
    public event EventHandler? SignOutRequested;

    private bool _full;
    private WindowStyle _prevStyle;
    private ResizeMode _prevResize;
    private WindowState _prevState;

    public MainWindow(ShellViewModel shell, string username)
    {
        InitializeComponent();
        DataContext = shell;
        UserText.Text = username;
        UpdateThemeButton();
        MouseWheel += (_, e) =>
        {
            if (Keyboard.Modifiers != ModifierKeys.Control) return;
            SetZoom(Zoom.ScaleX + (e.Delta > 0 ? 0.1 : -0.1));
            e.Handled = true;
        };
    }

    private void OnSignOut(object sender, RoutedEventArgs e) => SignOutRequested?.Invoke(this, EventArgs.Empty);

    // ---------------------------------------------------------------- light / dark

    private void OnToggleTheme(object sender, RoutedEventArgs e)
    {
        ThemeManager.Toggle();
        UpdateThemeButton();
    }

    // The button names the mode you will get when you click it.
    private void UpdateThemeButton() => ThemeBtn.Content = ThemeManager.IsDark ? "\u2600  Light mode" : "\u263E  Dark mode";

    // ---------------------------------------------------------------- window size

    private void OnMinimize(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private void OnMaximize(object sender, RoutedEventArgs e)
    {
        if (_full) ExitFullScreen();
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    private void OnStateChanged(object? sender, EventArgs e) =>
        MaxBtn.Content = WindowState == WindowState.Maximized ? "\u2750  Restore" : "\u25A1  Maximize";

    private void OnFullScreen(object sender, RoutedEventArgs e) { if (_full) ExitFullScreen(); else EnterFullScreen(); }

    private void EnterFullScreen()
    {
        _prevStyle = WindowStyle; _prevResize = ResizeMode; _prevState = WindowState;
        WindowStyle = WindowStyle.None;
        ResizeMode = ResizeMode.NoResize;
        WindowState = WindowState.Normal;      // re-apply Maximized so the taskbar is covered
        WindowState = WindowState.Maximized;
        _full = true;
        FullBtn.Content = "\u2715  Exit full screen";
    }

    private void ExitFullScreen()
    {
        WindowStyle = _prevStyle;
        ResizeMode = _prevResize;
        WindowState = _prevState == WindowState.Minimized ? WindowState.Normal : _prevState;
        _full = false;
        FullBtn.Content = "\u26F6  Full screen";
    }

    // ---------------------------------------------------------------- zoom

    private void OnZoomIn(object sender, RoutedEventArgs e) => SetZoom(Zoom.ScaleX + 0.1);
    private void OnZoomOut(object sender, RoutedEventArgs e) => SetZoom(Zoom.ScaleX - 0.1);

    private void SetZoom(double v)
    {
        v = Math.Round(Math.Clamp(v, 0.7, 1.8), 1);
        Zoom.ScaleX = v; Zoom.ScaleY = v;
    }

    private void OnKey(object sender, KeyEventArgs e)
    {
        var ctrl = Keyboard.Modifiers == ModifierKeys.Control;
        if (e.Key == Key.F11) { OnFullScreen(this, e); e.Handled = true; }
        else if (e.Key == Key.Escape && _full) { ExitFullScreen(); e.Handled = true; }
        else if (ctrl && (e.Key is Key.OemPlus or Key.Add)) { SetZoom(Zoom.ScaleX + 0.1); e.Handled = true; }
        else if (ctrl && (e.Key is Key.OemMinus or Key.Subtract)) { SetZoom(Zoom.ScaleX - 0.1); e.Handled = true; }
        else if (ctrl && (e.Key is Key.D0 or Key.NumPad0)) { SetZoom(1.0); e.Handled = true; }
    }
}
