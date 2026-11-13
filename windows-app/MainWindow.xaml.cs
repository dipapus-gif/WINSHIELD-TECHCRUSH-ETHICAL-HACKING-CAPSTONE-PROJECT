using System.Windows;
using WinShield.Ui;
using WinShield.ViewModels;

namespace WinShield;

public partial class MainWindow : Window
{
    public event EventHandler? SignOutRequested;

    public MainWindow(ShellViewModel shell, string username)
    {
        InitializeComponent();
        DataContext = shell;
        UserText.Text = username;
        UpdateThemeButton();
    }

    private void OnSignOut(object sender, RoutedEventArgs e) => SignOutRequested?.Invoke(this, EventArgs.Empty);

    private void OnToggleTheme(object sender, RoutedEventArgs e)
    {
        ThemeManager.Toggle();
        UpdateThemeButton();
    }

    // The button names the mode you will get when you click it.
    private void UpdateThemeButton() => ThemeBtn.Content = ThemeManager.IsDark ? "\u2600  Light mode" : "\u263E  Dark mode";
}
