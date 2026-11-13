using System.Windows;
using WinShield.ViewModels;

namespace WinShield;

public partial class MainWindow : Window
{
    public MainWindow(ShellViewModel shell)
    {
        InitializeComponent();
        DataContext = shell;
    }
}
