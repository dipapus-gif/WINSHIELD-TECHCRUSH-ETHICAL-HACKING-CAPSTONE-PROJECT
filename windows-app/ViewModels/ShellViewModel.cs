using WinShield.Data;
using WinShield.Services;
using WinShield.Ui;

namespace WinShield.ViewModels;

/// <summary>The main window: owns one view model per tab and the one-second refresh timer.</summary>
public sealed class ShellViewModel : ViewModelBase, IDisposable
{
    private readonly ProtectionService _protection;
    private readonly IUiServices _ui;
    private Timer? _timer;
    private int _ticks;

    public ShellViewModel(ProtectionService protection, IUiServices ui)
    {
        _protection = protection;
        _ui = ui;

        Dashboard = new DashboardViewModel(protection, ui);
        Incidents = new IncidentsViewModel(protection, ui);
        Folders = new FoldersViewModel(protection, ui);
        Recovery = new RecoveryViewModel(protection, ui);
        Settings = new SettingsViewModel(protection, ui);
        SystemHealth = new MainViewModel(new ScanRepository(), new ScanEngine());

        // "Alert users before taking potentially disruptive actions": the response engine asks through the UI.
        protection.Orchestrator.ConfirmAsync = ui.ConfirmAsync;

        protection.Problem += message => _ui.Post(() => Dashboard.SetMessage(message));
        protection.Orchestrator.IncidentChanged += incident => _ui.Post(() =>
            Dashboard.SetMessage($"ALERT: {incident.Title} ({incident.Severity}, {incident.Status}). Open the Incidents tab for details."));
    }

    public DashboardViewModel Dashboard { get; }
    public IncidentsViewModel Incidents { get; }
    public FoldersViewModel Folders { get; }
    public RecoveryViewModel Recovery { get; }
    public SettingsViewModel Settings { get; }
    public MainViewModel SystemHealth { get; }

    public async Task InitializeAsync()
    {
        try
        {
            // Loads settings, opens the database and turns protection back on if it was on last time.
            await Task.Run(_protection.Initialize);
        }
        catch (Exception ex)
        {
            Dashboard.SetMessage($"WinShield could not start protection: {ex.Message}");
        }

        Settings.Load();
        Dashboard.RefreshFast();
        await Task.WhenAll(
            Dashboard.RefreshSlowAsync(),
            Incidents.RefreshAsync(),
            Folders.RefreshAsync(),
            Recovery.RefreshAsync(),
            SystemHealth.InitializeAsync());

        _timer = new Timer(_ => Tick(), null, 1000, 1000);
    }

    private void Tick()
    {
        _ui.Post(() =>
        {
            Dashboard.RefreshFast();
            if (++_ticks % 4 == 0) _ = Dashboard.RefreshSlowAsync();
            RelayCommand.Requery();   // re-check which buttons are enabled
        });
    }

    public void Dispose() => _timer?.Dispose();
}
