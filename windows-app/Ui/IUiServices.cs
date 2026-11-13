namespace WinShield.Ui;

/// <summary>
/// Everything the view models need from the windowing system. The WPF implementation lives in
/// <c>WpfUiServices</c>; keeping it behind an interface keeps the view models free of WPF types.
/// </summary>
public interface IUiServices
{
    /// <summary>Runs <paramref name="action"/> on the UI thread without waiting for it.</summary>
    void Post(Action action);

    /// <summary>Asks a yes/no question. Safe to call from any thread.</summary>
    Task<bool> ConfirmAsync(string title, string message);

    void ShowMessage(string title, string message);

    /// <summary>Lets the user pick a folder. Returns null if they cancel.</summary>
    string? PickFolder(string title);

    /// <summary>Lets the user choose where to save a file. <paramref name="filter"/> is a Windows file dialog filter.</summary>
    string? PickSaveFile(string title, string suggestedName, string filter);

    /// <summary>Opens a file or folder with the default program.</summary>
    void Open(string path);

    /// <summary>Starts WinShield again with administrator rights (Windows asks the user to approve) and closes this copy.</summary>
    void RestartAsAdministrator();
}
