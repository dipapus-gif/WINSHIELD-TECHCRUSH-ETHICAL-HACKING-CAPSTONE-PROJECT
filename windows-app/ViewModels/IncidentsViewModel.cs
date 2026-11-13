using System.Collections.ObjectModel;
using WinShield.Core;
using WinShield.Models;
using WinShield.Services;
using WinShield.Ui;

namespace WinShield.ViewModels;

/// <summary>Incident history, the response actions for one incident, and report export.</summary>
public sealed class IncidentsViewModel : ViewModelBase
{
    private readonly ProtectionService _protection;
    private readonly IUiServices _ui;

    private Incident? _selected;
    private string _message = "";
    private int _refreshing;

    public IncidentsViewModel(ProtectionService protection, IUiServices ui)
    {
        _protection = protection;
        _ui = ui;

        // Orchestrator events arrive on background threads.
        _protection.Orchestrator.IncidentChanged += incident => _ui.Post(() => _ = RefreshAsync());
        _protection.Orchestrator.ActionRecorded += action => _ui.Post(() => _ = RefreshAsync());

        bool Has() => Selected is not null;
        bool HasProcess() => Selected?.ProcessId is not null;

        RefreshCommand = new RelayCommand(RefreshAsync);
        SuspendCommand = new RelayCommand(() => RunAsync(i => _protection.Orchestrator.SuspendIncidentProcess(i)), HasProcess);
        ResumeCommand = new RelayCommand(() => RunAsync(i => _protection.Orchestrator.ResumeIncidentProcess(i)), HasProcess);
        KillCommand = new RelayCommand(KillAsync, HasProcess);
        QuarantineCommand = new RelayCommand(QuarantineAsync, HasProcess);
        IsolateCommand = new RelayCommand(IsolateAsync, Has);
        RestoreNetworkCommand = new RelayCommand(() => RunAsync(i => _protection.Orchestrator.RestoreNetwork(i)), Has);
        ResolveCommand = new RelayCommand(() => SetStatusAsync("Resolved"), Has);
        FalsePositiveCommand = new RelayCommand(() => SetStatusAsync("FalsePositive"), Has);
        TrustCommand = new RelayCommand(TrustAsync, HasProcess);
        OpenEvidenceCommand = new RelayCommand(OpenEvidence, () => !string.IsNullOrEmpty(Selected?.EvidencePath));
        ExportHtmlCommand = new RelayCommand(() => ExportAsync("html", "HTML report (*.html)|*.html"));
        ExportCsvCommand = new RelayCommand(() => ExportAsync("csv", "Spreadsheet (*.csv)|*.csv"));
    }

    public ObservableCollection<Incident> Incidents { get; } = new();
    public ObservableCollection<IncidentAction> Actions { get; } = new();
    public ObservableCollection<string> AffectedFiles { get; } = new();
    public ObservableCollection<string> Recommendations { get; } = new();

    public RelayCommand RefreshCommand { get; }
    public RelayCommand SuspendCommand { get; }
    public RelayCommand ResumeCommand { get; }
    public RelayCommand KillCommand { get; }
    public RelayCommand QuarantineCommand { get; }
    public RelayCommand IsolateCommand { get; }
    public RelayCommand RestoreNetworkCommand { get; }
    public RelayCommand ResolveCommand { get; }
    public RelayCommand FalsePositiveCommand { get; }
    public RelayCommand TrustCommand { get; }
    public RelayCommand OpenEvidenceCommand { get; }
    public RelayCommand ExportHtmlCommand { get; }
    public RelayCommand ExportCsvCommand { get; }

    public string Message { get => _message; private set => SetField(ref _message, value); }

    public Incident? Selected
    {
        get => _selected;
        set
        {
            if (!SetField(ref _selected, value)) return;
            OnPropertyChanged(nameof(HasSelection));
            _ = LoadDetailsAsync(value);
        }
    }

    public bool HasSelection => Selected is not null;

    public async Task RefreshAsync()
    {
        if (Interlocked.Exchange(ref _refreshing, 1) == 1) return;
        try
        {
            var list = await Task.Run(() => _protection.Repo.GetIncidents(200));
            var keepId = Selected?.Id;

            Incidents.Clear();
            foreach (var i in list) Incidents.Add(i);

            // Re-select the same incident so the details pane does not jump while actions are recorded.
            if (keepId is not null)
            {
                var again = list.FirstOrDefault(i => i.Id == keepId);
                if (again is not null && !ReferenceEquals(again, _selected))
                {
                    _selected = again;
                    OnPropertyChanged(nameof(Selected));
                    await LoadDetailsAsync(again);
                }
            }
        }
        catch (Exception)
        {
            // A briefly locked database is not worth an error; the next refresh succeeds.
        }
        finally
        {
            Interlocked.Exchange(ref _refreshing, 0);
        }
    }

    private async Task LoadDetailsAsync(Incident? incident)
    {
        Actions.Clear();
        AffectedFiles.Clear();
        Recommendations.Clear();
        if (incident is null) return;

        try
        {
            var (actions, files, tips) = await Task.Run(() =>
            {
                var acts = _protection.Repo.GetActions(incident.Id);
                var affected = _protection.Repo.GetIncidentFiles(incident.Id, 500);
                var isolated = false;
                try { isolated = _protection.Network.IsIsolated(); } catch { /* status only */ }
                return (acts, affected, RecommendationEngine.ForIncident(incident, acts, isolated));
            });

            // The user may have clicked another incident while this was loading.
            if (!ReferenceEquals(_selected, incident)) return;

            foreach (var a in actions) Actions.Add(a);
            foreach (var f in files) AffectedFiles.Add(f);
            foreach (var t in tips) Recommendations.Add(t);
        }
        catch (Exception ex)
        {
            Message = $"Could not load incident details: {ex.Message}";
        }
    }

    private async Task RunAsync(Func<Incident, (bool Ok, string Message)> action)
    {
        var incident = Selected;
        if (incident is null) return;
        var result = await Task.Run(() => action(incident));
        Message = (result.Ok ? "" : "Not done: ") + result.Message;
        await RefreshAsync();
    }

    private async Task KillAsync()
    {
        var i = Selected;
        if (i is null) return;
        if (!await _ui.ConfirmAsync("Terminate process?",
                $"This will immediately end {i.ProcessText}. Unsaved work in that program is lost. Continue?")) return;
        await RunAsync(x => _protection.Orchestrator.KillIncidentProcess(x));
    }

    private async Task QuarantineAsync()
    {
        var i = Selected;
        if (i is null) return;
        if (!await _ui.ConfirmAsync("Quarantine program file?",
                $"The program file of {i.ProcessText} will be moved to a locked quarantine folder. You can restore it later. Continue?")) return;
        await RunAsync(x => _protection.Orchestrator.QuarantineIncidentImage(x));
    }

    private async Task IsolateAsync()
    {
        if (!await _ui.ConfirmAsync("Cut this PC off from the network?",
                "WinShield will add firewall rules that block all network traffic until you restore the network. " +
                "Remote connections to this PC will be lost. Continue?")) return;
        await RunAsync(x => _protection.Orchestrator.IsolateNetwork(x));
    }

    private async Task TrustAsync()
    {
        var i = Selected;
        if (i is null) return;
        if (!await _ui.ConfirmAsync("Always trust this program?",
                $"WinShield will never suspend, terminate or quarantine {i.ProcessName} again. Only do this for programs you recognise. Continue?")) return;
        _protection.Orchestrator.TrustIncidentProcess(i);
        Message = $"{i.ProcessName} was added to your trusted list.";
        await RefreshAsync();
    }

    private async Task SetStatusAsync(string status)
    {
        var i = Selected;
        if (i is null) return;
        await Task.Run(() => _protection.Orchestrator.SetStatus(i, status));
        Message = status == "FalsePositive" ? "Marked as a false positive." : "Marked as resolved.";
        await RefreshAsync();
    }

    private void OpenEvidence()
    {
        if (!string.IsNullOrEmpty(Selected?.EvidencePath)) _ui.Open(Selected!.EvidencePath!);
    }

    private async Task ExportAsync(string extension, string filter)
    {
        var path = _ui.PickSaveFile("Save security report", ReportService.DefaultFileName(extension), filter);
        if (path is null) return;

        var saved = await Task.Run(() => _protection.Reports.Save(_protection.Reports.Collect(), path));
        Message = $"Report saved to {saved}";
        _ui.Open(saved);
    }
}
