using System.Collections.ObjectModel;
using WinShield.Core;
using WinShield.Models;
using WinShield.Services;
using WinShield.Ui;

namespace WinShield.ViewModels;

/// <summary>The live protection dashboard: status, threat level, suspicious processes and recent incidents.</summary>
public sealed class DashboardViewModel : ViewModelBase
{
    private readonly ProtectionService _protection;
    private readonly IUiServices _ui;

    private bool _isProtected;
    private bool _emergency;
    private string _statusTitle = "Protection is off";
    private string _statusDetail = "";
    private string _message = "";
    private string _threatLevel = "Quiet";
    private LiveMetrics _metrics = LiveMetrics.Empty;
    private ProtectionStats _stats = new(0, 0, 0, 0, 0);
    private string _networkText = "";
    private int _refreshingSlow;

    public DashboardViewModel(ProtectionService protection, IUiServices ui)
    {
        _protection = protection;
        _ui = ui;

        ToggleProtectionCommand = new RelayCommand(ToggleAsync);
        EmergencyCommand = new RelayCommand(EmergencyAsync);
        ResumeAllCommand = new RelayCommand(ResumeAll, () => _protection.Controller.Suspended.Count > 0);
        RestartAsAdminCommand = new RelayCommand(() => _ui.RestartAsAdministrator(), () => !Administrator);
    }

    public ObservableCollection<SuspiciousProcess> Processes { get; } = new();
    public ObservableCollection<Incident> RecentIncidents { get; } = new();
    public ObservableCollection<FileActivity> LiveActivity { get; } = new();

    public RelayCommand ToggleProtectionCommand { get; }
    public RelayCommand EmergencyCommand { get; }
    public RelayCommand ResumeAllCommand { get; }
    public RelayCommand RestartAsAdminCommand { get; }

    public bool IsProtected { get => _isProtected; private set { if (SetField(ref _isProtected, value)) { OnPropertyChanged(nameof(ToggleText)); } } }
    public bool Emergency { get => _emergency; private set { if (SetField(ref _emergency, value)) OnPropertyChanged(nameof(EmergencyText)); } }
    public string StatusTitle { get => _statusTitle; private set => SetField(ref _statusTitle, value); }
    public string StatusDetail { get => _statusDetail; private set => SetField(ref _statusDetail, value); }
    public string Message { get => _message; private set => SetField(ref _message, value); }
    public string ThreatLevel { get => _threatLevel; private set => SetField(ref _threatLevel, value); }
    public string NetworkText { get => _networkText; private set => SetField(ref _networkText, value); }

    public string ToggleText => IsProtected ? "Turn protection off" : "Turn protection on";
    public string EmergencyText => Emergency ? "Release emergency protection" : "Emergency protection";

    public int Modified => _metrics.Modified;
    public int Renamed => _metrics.Renamed;
    public int Deleted => _metrics.Deleted;
    public int HighEntropy => _metrics.HighEntropy;
    public double ThreatScore => _metrics.Score;

    public int TotalIncidents => _stats.TotalIncidents;
    public int OpenIncidents => _stats.OpenIncidents;
    public int Critical30d => _stats.CriticalIncidents30d;
    public int High30d => _stats.HighIncidents30d;
    public int FileEvents24h => _stats.FileEvents24h;

    public bool Administrator => AdminHelper.IsAdministrator;

    public string AdminText => Administrator
        ? "Running as administrator: all protections are available."
        : "Not running as administrator: command-line monitoring, network isolation and Controlled Folder Access are unavailable.";

    /// <summary>Shows a one-line notice under the status banner (alerts, problems, results of actions).</summary>
    public void SetMessage(string text) => Message = text;

    /// <summary>Cheap values, refreshed every second on the UI thread.</summary>
    public void RefreshFast()
    {
        var settings = _protection.Settings.Current;
        IsProtected = _protection.IsRunning;
        Emergency = _protection.Orchestrator.EmergencyActive;

        _metrics = _protection.Detection.Metrics;
        foreach (var name in new[] { nameof(Modified), nameof(Renamed), nameof(Deleted), nameof(HighEntropy), nameof(ThreatScore) })
            OnPropertyChanged(name);

        ThreatLevel = _metrics.Score switch
        {
            < 25 => "Quiet",
            < 50 => "Elevated",
            < 75 => "High",
            _ => "Critical"
        };

        StatusTitle = Emergency ? "EMERGENCY PROTECTION ACTIVE" : IsProtected ? "Protected" : "Protection is off";
        StatusDetail = IsProtected
            ? $"Watching {_protection.Files.WatchedFolders.Count} folder(s), {_protection.Honeypots.Count} decoy file(s). Response mode: {ModeText(settings.ResponseMode)}."
            : "Turn protection on to start watching your folders.";

        Replace(Processes, _protection.Behavior.Current.OrderByDescending(p => p.Score).Take(12));
        Replace(LiveActivity, _protection.RecentActivity().Reverse().Take(40));
    }

    /// <summary>Database-backed values, refreshed every few seconds in the background.</summary>
    public async Task RefreshSlowAsync()
    {
        if (Interlocked.Exchange(ref _refreshingSlow, 1) == 1) return;
        try
        {
            var (stats, incidents, isolated) = await Task.Run(() =>
            {
                var isolatedNow = false;
                try { isolatedNow = _protection.Network.IsIsolated(); } catch { /* status only */ }
                return (_protection.Repo.GetStats(), _protection.Repo.GetIncidents(6), isolatedNow);
            });

            _ui.Post(() =>
            {
                _stats = stats;
                foreach (var name in new[] { nameof(TotalIncidents), nameof(OpenIncidents), nameof(Critical30d), nameof(High30d), nameof(FileEvents24h) })
                    OnPropertyChanged(name);
                Replace(RecentIncidents, incidents);
                NetworkText = isolated ? "NETWORK ISOLATED: this PC is cut off from the network." : "Network: connected";
            });
        }
        catch (Exception)
        {
            // A locked database for a moment is not worth an error message; the next refresh will succeed.
        }
        finally
        {
            Interlocked.Exchange(ref _refreshingSlow, 0);
        }
    }

    private static string ModeText(ResponseMode mode) => mode switch
    {
        ResponseMode.MonitorOnly => "monitor only",
        ResponseMode.AskFirst => "ask before acting",
        _ => "automatic containment"
    };

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> items)
    {
        target.Clear();
        foreach (var item in items) target.Add(item);
    }

    private async Task ToggleAsync()
    {
        if (_protection.IsRunning)
        {
            if (!await _ui.ConfirmAsync("Turn protection off?",
                    "WinShield will stop watching your folders, so ransomware would no longer be detected. Turn it off anyway?"))
                return;
            await Task.Run(() => _protection.Stop());
            Message = "Protection turned off.";
        }
        else
        {
            var result = await Task.Run(() => _protection.Start());
            Message = result.Message;
        }
        RefreshFast();
    }

    private async Task EmergencyAsync()
    {
        if (!_protection.Orchestrator.EmergencyActive)
        {
            var ok = await _ui.ConfirmAsync("Activate emergency protection?",
                "WinShield will suspend processes that look like ransomware and, if it has administrator rights, turn on " +
                "Controlled Folder Access. It will then ask whether to cut this PC off from the network.\n\nContinue?");
            if (!ok) return;
            await _protection.Orchestrator.ActivateEmergencyManualAsync();
            Message = "Emergency protection is active. Review the Incidents tab.";
        }
        else
        {
            await _protection.Orchestrator.ReleaseEmergencyAsync();
            Message = "Emergency protection released. Suspended processes were resumed and the network was restored.";
        }
        RefreshFast();
    }

    private void ResumeAll()
    {
        var count = _protection.Controller.ResumeAll();
        Message = $"Resumed {count} suspended process(es).";
    }
}
