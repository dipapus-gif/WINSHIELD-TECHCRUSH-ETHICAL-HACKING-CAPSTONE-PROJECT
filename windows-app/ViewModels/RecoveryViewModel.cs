using System.Collections.ObjectModel;
using WinShield.Core;
using WinShield.Models;
using WinShield.Services;
using WinShield.Ui;

namespace WinShield.ViewModels;

/// <summary>Recovery points (protected backups), verified restore, and quarantined files.</summary>
public sealed class RecoveryViewModel : ViewModelBase
{
    private readonly ProtectionService _protection;
    private readonly IUiServices _ui;

    private BackupPoint? _selectedPoint;
    private QuarantineItem? _selectedQuarantine;
    private string _message = "";
    private string _statusText = "";
    private bool _busy;

    public RecoveryViewModel(ProtectionService protection, IUiServices ui)
    {
        _protection = protection;
        _ui = ui;

        bool HasPoint() => SelectedPoint is not null && !Busy;
        CreatePointCommand = new RelayCommand(CreatePointAsync, () => !Busy);
        VerifyCommand = new RelayCommand(VerifyAsync, HasPoint);
        RestoreToFolderCommand = new RelayCommand(RestoreToFolderAsync, HasPoint);
        RestoreInPlaceCommand = new RelayCommand(RestoreInPlaceAsync, HasPoint);
        PruneCommand = new RelayCommand(PruneAsync, () => !Busy);
        RestoreQuarantinedCommand = new RelayCommand(RestoreQuarantinedAsync, () => SelectedQuarantine is { Restored: false });
        DeleteQuarantinedCommand = new RelayCommand(DeleteQuarantinedAsync, () => SelectedQuarantine is not null);
    }

    public ObservableCollection<BackupPoint> Points { get; } = new();
    public ObservableCollection<QuarantineItem> Quarantined { get; } = new();
    public IReadOnlyList<string> Guidance { get; } = RecommendationEngine.RecoveryGuidance();

    public RelayCommand CreatePointCommand { get; }
    public RelayCommand VerifyCommand { get; }
    public RelayCommand RestoreToFolderCommand { get; }
    public RelayCommand RestoreInPlaceCommand { get; }
    public RelayCommand PruneCommand { get; }
    public RelayCommand RestoreQuarantinedCommand { get; }
    public RelayCommand DeleteQuarantinedCommand { get; }

    public BackupPoint? SelectedPoint { get => _selectedPoint; set => SetField(ref _selectedPoint, value); }
    public QuarantineItem? SelectedQuarantine { get => _selectedQuarantine; set => SetField(ref _selectedQuarantine, value); }
    public string Message { get => _message; private set => SetField(ref _message, value); }
    public string StatusText { get => _statusText; private set => SetField(ref _statusText, value); }
    public bool Busy { get => _busy; private set => SetField(ref _busy, value); }

    public async Task RefreshAsync()
    {
        try
        {
            var (points, quarantined, age) = await Task.Run(() =>
                (_protection.Recovery.List(), _protection.Repo.GetQuarantine(), _protection.Recovery.AgeOfNewestGoodPoint()));

            var keep = SelectedPoint?.Id;
            Points.Clear();
            foreach (var p in points) Points.Add(p);
            SelectedPoint = keep is null ? null : Points.FirstOrDefault(p => p.Id == keep);

            Quarantined.Clear();
            foreach (var q in quarantined) Quarantined.Add(q);

            StatusText = age is null
                ? "No recovery point yet. Create one now so you have something to restore from."
                : $"Newest clean recovery point is {Describe(age.Value)} old.";
        }
        catch (Exception ex)
        {
            StatusText = $"Could not read recovery points: {ex.Message}";
        }
    }

    private static string Describe(TimeSpan span) =>
        span.TotalHours < 1 ? $"{Math.Max(1, (int)span.TotalMinutes)} minute(s)"
        : span.TotalDays < 2 ? $"{(int)span.TotalHours} hour(s)"
        : $"{(int)span.TotalDays} day(s)";

    private async Task CreatePointAsync()
    {
        Busy = true;
        Message = "Creating recovery point... large folders can take a few minutes.";
        try
        {
            // Mark it as tainted when an incident is open, so a point taken mid-attack is never trusted as clean.
            var tainted = _protection.Orchestrator.EmergencyActive;
            var point = await Task.Run(() => _protection.Recovery.CreatePoint("Manual recovery point", tainted));
            Message = $"Recovery point created: {point.FileCount:N0} files, {point.SizeText}" +
                      (point.Skipped > 0 ? $", {point.Skipped} skipped (too large or unreadable)." : ".");
            await RefreshAsync();
        }
        catch (Exception ex)
        {
            Message = $"Could not create a recovery point: {ex.Message}";
        }
        finally { Busy = false; }
    }

    private async Task VerifyAsync()
    {
        var point = SelectedPoint;
        if (point is null) return;
        Busy = true;
        Message = "Verifying stored files...";
        try
        {
            var (checkedCount, bad) = await Task.Run(() => _protection.Recovery.Verify(point.Id));
            Message = bad.Count == 0
                ? $"Verified: all {checkedCount:N0} stored files match their recorded hashes."
                : $"PROBLEM: {bad.Count} of {checkedCount:N0} stored files are missing or damaged. " + string.Join("; ", bad.Take(3));
        }
        catch (Exception ex)
        {
            Message = $"Could not verify: {ex.Message}";
        }
        finally { Busy = false; }
    }

    private async Task RestoreToFolderAsync()
    {
        var point = SelectedPoint;
        if (point is null) return;
        var folder = _ui.PickFolder("Choose where to put the restored copies");
        if (string.IsNullOrWhiteSpace(folder)) return;
        await RestoreAsync(point, folder, inPlace: false);
    }

    private async Task RestoreInPlaceAsync()
    {
        var point = SelectedPoint;
        if (point is null) return;

        var warning = point.Tainted
            ? "This point was created during an incident, so it may contain damaged files. Prefer an earlier point.\n\n"
            : "";
        if (!await _ui.ConfirmAsync("Restore over the original files?",
                warning + "Files that are missing or different will be replaced with the saved versions. The versions being replaced are " +
                "kept in WinShield's backup folder as evidence. Restore only after the threat has been removed. Continue?")) return;

        await RestoreAsync(point, null, inPlace: true);
    }

    private async Task RestoreAsync(BackupPoint point, string? destination, bool inPlace)
    {
        Busy = true;
        Message = "Restoring and checking every file...";
        try
        {
            var result = await Task.Run(() => _protection.Recovery.Restore(point.Id, destination, inPlace));
            Message = result.Success
                ? $"Restored {result.Restored:N0} file(s) to {result.Destination}; {result.Verified:N0} verified against their hashes" +
                  (inPlace ? $", {result.AlreadyCurrent:N0} were already correct." : ".")
                : $"Restored {result.Restored:N0} file(s) but {result.Failures.Count} failed: " + string.Join("; ", result.Failures.Take(3));
            if (!inPlace && result.Success) _ui.Open(result.Destination);
        }
        catch (Exception ex)
        {
            Message = $"Restore failed: {ex.Message}";
        }
        finally { Busy = false; }
    }

    private async Task PruneAsync()
    {
        Busy = true;
        try
        {
            var removed = await Task.Run(() => _protection.Recovery.Prune());
            Message = $"Cleanup finished. Removed {removed} unused stored file(s).";
            await RefreshAsync();
        }
        finally { Busy = false; }
    }

    private async Task RestoreQuarantinedAsync()
    {
        var item = SelectedQuarantine;
        if (item is null) return;
        if (!await _ui.ConfirmAsync("Restore quarantined file?",
                $"{item.OriginalPath} will be put back where it was. Only restore it if you are sure it is safe. Continue?")) return;

        var (ok, message) = await Task.Run(() => _protection.Quarantine.Restore(item));
        Message = (ok ? "" : "Not restored: ") + message;
        await RefreshAsync();
    }

    private async Task DeleteQuarantinedAsync()
    {
        var item = SelectedQuarantine;
        if (item is null) return;
        if (!await _ui.ConfirmAsync("Delete permanently?",
                "The quarantined copy will be deleted for good. Continue?")) return;

        var (ok, message) = await Task.Run(() => _protection.Quarantine.Delete(item));
        Message = (ok ? "" : "Not deleted: ") + message;
        await RefreshAsync();
    }
}
