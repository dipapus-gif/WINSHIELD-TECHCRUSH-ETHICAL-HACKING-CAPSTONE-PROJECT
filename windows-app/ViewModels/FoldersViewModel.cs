using System.Collections.ObjectModel;
using WinShield.Core;
using WinShield.Models;
using WinShield.Services;
using WinShield.Ui;

namespace WinShield.ViewModels;

/// <summary>Protected folders, decoy (honeypot) files and the file-integrity baseline.</summary>
public sealed class FoldersViewModel : ViewModelBase
{
    private readonly ProtectionService _protection;
    private readonly IUiServices _ui;

    private string? _selectedFolder;
    private string _message = "";
    private string _baselineText = "No baseline yet.";
    private string _integritySummary = "";
    private string _progressText = "";
    private bool _busy;

    public FoldersViewModel(ProtectionService protection, IUiServices ui)
    {
        _protection = protection;
        _ui = ui;

        AddFolderCommand = new RelayCommand(AddFolderAsync);
        RemoveFolderCommand = new RelayCommand(RemoveFolderAsync, () => SelectedFolder is not null);
        DeployDecoysCommand = new RelayCommand(DeployDecoysAsync, () => !Busy);
        RemoveDecoysCommand = new RelayCommand(RemoveDecoysAsync, () => !Busy);
        BuildBaselineCommand = new RelayCommand(BuildBaselineAsync, () => !Busy);
        CompareCommand = new RelayCommand(CompareAsync, () => !Busy);
        EnableCfaCommand = new RelayCommand(EnableCfaAsync, () => !Busy);
        DisableCfaCommand = new RelayCommand(DisableCfaAsync, () => !Busy);
    }

    public ObservableCollection<string> ProtectedFolders { get; } = new();
    public ObservableCollection<HoneypotFile> Decoys { get; } = new();
    public ObservableCollection<IntegrityChange> Changes { get; } = new();

    public RelayCommand AddFolderCommand { get; }
    public RelayCommand RemoveFolderCommand { get; }
    public RelayCommand DeployDecoysCommand { get; }
    public RelayCommand RemoveDecoysCommand { get; }
    public RelayCommand BuildBaselineCommand { get; }
    public RelayCommand CompareCommand { get; }
    public RelayCommand EnableCfaCommand { get; }
    public RelayCommand DisableCfaCommand { get; }

    private string _cfaStatus = "Checking...";
    public string CfaStatus { get => _cfaStatus; private set => SetField(ref _cfaStatus, value); }

    public string? SelectedFolder { get => _selectedFolder; set => SetField(ref _selectedFolder, value); }
    public string Message { get => _message; private set => SetField(ref _message, value); }
    public string BaselineText { get => _baselineText; private set => SetField(ref _baselineText, value); }
    public string IntegritySummary { get => _integritySummary; private set => SetField(ref _integritySummary, value); }
    public string ProgressText { get => _progressText; private set => SetField(ref _progressText, value); }
    public bool Busy { get => _busy; private set => SetField(ref _busy, value); }

    public async Task RefreshAsync()
    {
        ProtectedFolders.Clear();
        foreach (var f in _protection.Settings.Current.ProtectedFolders) ProtectedFolders.Add(f);

        var info = _protection.Integrity.BaselineInfo;
        BaselineText = info.CreatedUtc is null
            ? "No baseline yet. Build one while you know your files are clean."
            : $"Baseline: {info.Count:N0} files, built {info.CreatedUtc.Value.ToLocalTime():g}.";

        try
        {
            var decoys = await Task.Run(() => _protection.Honeypots.ListWithStatus());
            Decoys.Clear();
            foreach (var d in decoys) Decoys.Add(d);
        }
        catch (Exception ex)
        {
            Message = $"Could not list decoy files: {ex.Message}";
        }

        CfaStatus = await Task.Run(_protection.Cfa.GetStatus);
    }

    private async Task EnableCfaAsync()
    {
        if (!AdminHelper.IsAdministrator)
        {
            if (await _ui.ConfirmAsync("Administrator rights needed",
                    "Controlled Folder Access is a Windows Defender setting, so changing it needs administrator rights.\n\n" +
                    "Restart WinShield as administrator now?"))
                _ui.RestartAsAdministrator();
            return;
        }

        if (!await _ui.ConfirmAsync("Turn on Controlled Folder Access?",
                "Windows will stop programs it does not recognise from changing files in your protected folders. " +
                "This blocks ransomware, but it can also block a legitimate program that has not been allowed yet " +
                "(you can allow it in Windows Security > Ransomware protection).\n\nTurn it on?")) return;

        Busy = true;
        try
        {
            var folders = _protection.Settings.Current.ProtectedFolders.ToList();
            var (_, message) = await Task.Run(() => _protection.Cfa.Enable(folders));
            Message = message;
            CfaStatus = await Task.Run(_protection.Cfa.GetStatus);
        }
        finally { Busy = false; }
    }

    private async Task DisableCfaAsync()
    {
        if (!AdminHelper.IsAdministrator)
        {
            Message = "Controlled Folder Access needs administrator rights. Use 'Turn on' to restart WinShield as administrator.";
            return;
        }

        if (!await _ui.ConfirmAsync("Turn off Controlled Folder Access?",
                "Your protected folders will no longer be shielded from untrusted programs. Turn it off anyway?")) return;

        Busy = true;
        try
        {
            var (_, message) = await Task.Run(_protection.Cfa.Disable);
            Message = message;
            CfaStatus = await Task.Run(_protection.Cfa.GetStatus);
        }
        finally { Busy = false; }
    }

    private async Task AddFolderAsync()
    {
        var folder = _ui.PickFolder("Choose a folder to protect");
        if (string.IsNullOrWhiteSpace(folder)) return;

        var settings = _protection.Settings.Current;
        var full = Path.GetFullPath(folder);
        if (settings.ProtectedFolders.Any(f => string.Equals(Path.GetFullPath(f), full, AppPaths.PathComparison)))
        {
            Message = "That folder is already protected.";
            return;
        }
        if (AppPaths.IsInternal(full))
        {
            Message = "WinShield's own data folder cannot be protected.";
            return;
        }

        settings.ProtectedFolders.Add(full);
        await ApplyFolderChangeAsync($"Now protecting {full}.");
    }

    private async Task RemoveFolderAsync()
    {
        var folder = SelectedFolder;
        if (folder is null) return;
        if (!await _ui.ConfirmAsync("Stop protecting this folder?",
                $"WinShield will stop watching {folder}. Ransomware there would no longer be detected. Continue?")) return;

        _protection.Settings.Current.ProtectedFolders.RemoveAll(f => string.Equals(f, folder, StringComparison.OrdinalIgnoreCase));
        await ApplyFolderChangeAsync($"No longer protecting {folder}.");
    }

    /// <summary>Saves the folder list and, if protection is running, restarts it so the watchers pick up the change.</summary>
    private async Task ApplyFolderChangeAsync(string successMessage)
    {
        await Task.Run(() =>
        {
            _protection.Settings.Save();
            if (_protection.IsRunning)
            {
                _protection.Stop(remember: false);
                _protection.Start();
            }
        });
        Message = successMessage;
        await RefreshAsync();
    }

    private async Task DeployDecoysAsync()
    {
        Busy = true;
        try
        {
            var folders = _protection.Settings.Current.ProtectedFolders.Where(Directory.Exists).ToList();
            var count = await Task.Run(() => _protection.Honeypots.Deploy(folders));
            Message = $"{count} decoy file(s) are in place. Nothing legitimate should ever touch them.";
            await RefreshAsync();
        }
        finally { Busy = false; }
    }

    private async Task RemoveDecoysAsync()
    {
        if (!await _ui.ConfirmAsync("Remove decoy files?",
                "Without decoys, WinShield loses its fastest ransomware tripwire. Remove them anyway?")) return;
        Busy = true;
        try
        {
            var removed = await Task.Run(() => _protection.Honeypots.Remove());
            Message = $"Removed {removed} decoy file(s).";
            await RefreshAsync();
        }
        finally { Busy = false; }
    }

    private async Task BuildBaselineAsync()
    {
        if (_protection.Integrity.BaselineInfo.CreatedUtc is not null &&
            !await _ui.ConfirmAsync("Replace the baseline?",
                "This records the current state of your files as the new known-good state. If ransomware already changed " +
                "files, those changes would be accepted as normal. Continue only if you trust your files right now.")) return;

        Busy = true;
        ProgressText = "Hashing files...";
        try
        {
            var progress = new Progress<int>(n => ProgressText = $"Hashed {n:N0} files...");
            var count = await Task.Run(() => _protection.Integrity.BuildBaseline(progress));
            Message = $"Baseline recorded for {count:N0} files.";
            IntegritySummary = "";
            Changes.Clear();
            await RefreshAsync();
        }
        finally
        {
            ProgressText = "";
            Busy = false;
        }
    }

    private async Task CompareAsync()
    {
        if (_protection.Integrity.BaselineInfo.CreatedUtc is null)
        {
            Message = "Build a baseline first, then compare against it later.";
            return;
        }

        Busy = true;
        ProgressText = "Comparing files...";
        try
        {
            var progress = new Progress<int>(n => ProgressText = $"Checked {n:N0} files...");
            var (report, changes) = await Task.Run(() => _protection.Integrity.Compare(progress));

            Changes.Clear();
            foreach (var c in changes) Changes.Add(c);

            IntegritySummary = report.HasChanges
                ? $"{report.Modified.Count} modified, {report.Deleted.Count} deleted, {report.Renamed.Count} renamed, " +
                  $"{report.Added.Count} new, {report.Unchanged:N0} unchanged."
                : $"No differences: all {report.Unchanged:N0} files match the baseline.";
            if (report.Unreadable > 0) IntegritySummary += $" {report.Unreadable} file(s) could not be read.";
            Message = "Integrity comparison finished.";
        }
        finally
        {
            ProgressText = "";
            Busy = false;
        }
    }
}
