using System.Windows.Input;

namespace WinShield.ViewModels;

/// <summary>
/// A command that runs a method, sync or async. Whether it can run is re-checked whenever
/// <see cref="Requery"/> is called (the shell does that on a timer and after every command).
/// </summary>
public sealed class RelayCommand : ICommand
{
    private static event EventHandler? GlobalRequery;

    /// <summary>Called with any exception a command throws. Set once at startup.</summary>
    public static Action<Exception>? ErrorHandler { get; set; }

    public static void Requery() => GlobalRequery?.Invoke(null, EventArgs.Empty);

    private readonly Func<Task> _execute;
    private readonly Func<bool>? _canExecute;
    private bool _running;

    public RelayCommand(Func<Task> execute, Func<bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
        : this(() => { execute(); return Task.CompletedTask; }, canExecute)
    {
    }

    public event EventHandler? CanExecuteChanged
    {
        add => GlobalRequery += value;
        remove => GlobalRequery -= value;
    }

    // A command that is still running cannot be started a second time (stops double clicks).
    public bool CanExecute(object? parameter) => !_running && (_canExecute?.Invoke() ?? true);

    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter)) return;
        _running = true;
        Requery();
        try
        {
            await _execute();
        }
        catch (Exception ex)
        {
            ErrorHandler?.Invoke(ex);
        }
        finally
        {
            _running = false;
            Requery();
        }
    }
}
