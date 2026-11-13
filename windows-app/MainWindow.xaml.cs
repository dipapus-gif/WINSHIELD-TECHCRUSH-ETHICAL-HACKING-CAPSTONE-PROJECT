using System.Windows;
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
    }

    private void OnSignOut(object sender, RoutedEventArgs e) => SignOutRequested?.Invoke(this, EventArgs.Empty);
}
