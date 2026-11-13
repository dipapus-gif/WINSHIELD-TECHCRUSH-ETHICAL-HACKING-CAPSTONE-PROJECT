using System.Collections.ObjectModel;
using WinShield.Data;
using WinShield.Models;
using WinShield.Services;

namespace WinShield.ViewModels;

public sealed class MainViewModel : ViewModelBase
{
    private readonly ScanRepository _repo;
    private readonly ScanEngine _engine;

    private bool _isScanning;
    private int _score;
    private bool _hasScore;
    private string _statusText = "Ready. Press Run scan to check this PC.";
    private ScanRecord? _selectedScan;

    public MainViewModel(ScanRepository repo, ScanEngine engine)
    {
        _repo = repo;
        _engine = engine;

        ScanCommand = new RelayCommand(RunScanAsync, () => !IsScanning);
        DeleteScanCommand = new RelayCommand(DeleteSelectedScan, () => SelectedScan is not null);
    }

    public ObservableCollection<CheckResult> Results { get; } = new();
    public ObservableCollection<ScanRecord> History { get; } = new();
    public ObservableCollection<CheckResult> HistoryResults { get; } = new();

    public RelayCommand ScanCommand { get; }
    public RelayCommand DeleteScanCommand { get; }

    public bool IsScanning
    {
        get => _isScanning;
        private set => SetField(ref _isScanning, value);
    }

    public int Score
    {
        get => _score;
        private set
        {
            if (SetField(ref _score, value)) OnPropertyChanged(nameof(Grade));
        }
    }

    public bool HasScore
    {
        get => _hasScore;
        private set => SetField(ref _hasScore, value);
    }

    public string Grade => !HasScore ? "-" : Score switch
    {
        >= 90 => "A",
        >= 75 => "B",
        >= 60 => "C",
        >= 40 => "D",
        _ => "F"
    };

    public string StatusText
    {
        get => _statusText;
        private set => SetField(ref _statusText, value);
    }

    public ScanRecord? SelectedScan
    {
        get => _selectedScan;
        set
        {
            if (!SetField(ref _selectedScan, value)) return;
            LoadHistoryResults();
        }
    }

    public async Task InitializeAsync()
    {
        try
        {
            await Task.Run(_repo.Initialize);
            await LoadHistoryAsync();
        }
        catch (Exception ex)
        {
            StatusText = $"Could not open the scan history database: {ex.Message}";
        }
    }

    private async Task RunScanAsync()
    {
        IsScanning = true;
        StatusText = "Scanning...";
        try
        {
            var startedUtc = DateTime.UtcNow;
            var results = await Task.Run(_engine.Run);
            var summary = ScanEngine.Summarize(results);

            Results.Clear();
            foreach (var r in results) Results.Add(r);

            Score = summary.Score;
            HasScore = true;
            OnPropertyChanged(nameof(Grade));

            var record = new ScanRecord
            {
                StartedUtc = startedUtc,
                MachineName = Environment.MachineName,
                Score = summary.Score,
                PassCount = summary.PassCount,
                WarnCount = summary.WarnCount,
                FailCount = summary.FailCount
            };

            await Task.Run(() => _repo.SaveScan(record, results));
            await LoadHistoryAsync();

            StatusText = $"Scan finished: {summary.PassCount} passed, {summary.WarnCount} warnings, {summary.FailCount} failed.";
        }
        catch (Exception ex)
        {
            StatusText = $"Scan failed: {ex.Message}";
        }
        finally
        {
            IsScanning = false;
        }
    }

    private async Task LoadHistoryAsync()
    {
        var history = await Task.Run(() => _repo.GetHistory());
        History.Clear();
        foreach (var h in history) History.Add(h);

        // Show the latest saved score on startup before any new scan has run.
        if (!HasScore && history.Count > 0)
        {
            Score = history[0].Score;
            HasScore = true;
            OnPropertyChanged(nameof(Grade));
            var latest = await Task.Run(() => _repo.GetResults(history[0].Id));
            Results.Clear();
            foreach (var r in latest) Results.Add(r);
            StatusText = $"Showing the last scan from {history[0].StartedLocal:g}. Press Run scan to refresh.";
        }
    }

    private void LoadHistoryResults()
    {
        HistoryResults.Clear();
        if (SelectedScan is null) return;
        foreach (var r in _repo.GetResults(SelectedScan.Id)) HistoryResults.Add(r);
    }

    private async Task DeleteSelectedScan()
    {
        if (SelectedScan is null) return;
        var id = SelectedScan.Id;
        await Task.Run(() => _repo.DeleteScan(id));
        SelectedScan = null;
        await LoadHistoryAsync();
    }
}
