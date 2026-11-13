using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;

namespace WinShield.Ui;

/// <summary>The WPF implementation of <see cref="IUiServices"/>. Every method is safe to call from any thread.</summary>
public sealed class WpfUiServices : IUiServices
{
    private readonly Dispatcher _dispatcher = Application.Current.Dispatcher;

    private Window? Owner => Application.Current.MainWindow is { IsLoaded: true } w ? w : null;

    private T OnUiThread<T>(Func<T> work) =>
        _dispatcher.CheckAccess() ? work() : _dispatcher.Invoke(work);

    public void Post(Action action) => _dispatcher.BeginInvoke(action);

    public Task<bool> ConfirmAsync(string title, string message)
    {
        var done = new TaskCompletionSource<bool>();
        _dispatcher.BeginInvoke(() =>
        {
            try
            {
                var answer = MessageBox.Show(message, title, MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No);
                done.SetResult(answer == MessageBoxResult.Yes);
            }
            catch (Exception ex)
            {
                done.SetException(ex);
            }
        });
        return done.Task;
    }

    public void ShowMessage(string title, string message) =>
        _dispatcher.BeginInvoke(() => MessageBox.Show(message, title, MessageBoxButton.OK, MessageBoxImage.Information));

    public string? PickFolder(string title) => OnUiThread(() =>
    {
        var dialog = new OpenFolderDialog { Title = title };
        var accepted = Owner is { } owner ? dialog.ShowDialog(owner) : dialog.ShowDialog();
        return accepted == true ? dialog.FolderName : null;
    });

    public string? PickSaveFile(string title, string suggestedName, string filter) => OnUiThread(() =>
    {
        var dialog = new SaveFileDialog { Title = title, FileName = suggestedName, Filter = filter, OverwritePrompt = true };
        var accepted = Owner is { } owner ? dialog.ShowDialog(owner) : dialog.ShowDialog();
        return accepted == true ? dialog.FileName : null;
    });

    public void Open(string path)
    {
        try
        {
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            ShowMessage("WinShield", $"Could not open {path}: {ex.Message}");
        }
    }

    public void RestartAsAdministrator()
    {
        try
        {
            var exe = Environment.ProcessPath;
            if (string.IsNullOrEmpty(exe)) throw new InvalidOperationException("The program path is unknown.");

            // "runas" shows the Windows approval prompt. If the user declines, Windows throws error 1223.
            Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true, Verb = "runas" });
            _dispatcher.BeginInvoke(() => Application.Current.Shutdown());
        }
        catch (Win32Exception)
        {
            ShowMessage("WinShield", "Administrator approval was cancelled, so WinShield is still running without it.");
        }
        catch (Exception ex)
        {
            ShowMessage("WinShield", $"Could not restart as administrator: {ex.Message}");
        }
    }
}
