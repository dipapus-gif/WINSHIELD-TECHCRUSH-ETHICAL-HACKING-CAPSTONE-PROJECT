using System.Collections.Concurrent;
using WinShield.Core;
using WinShield.Data;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Creates every service, connects the detectors to the response engine and runs the protection on and off.
/// The user interface only talks to this class.
/// </summary>
public sealed class ProtectionService : IDisposable
{
    private const int RecentActivityLimit = 1500;

    private readonly ConcurrentQueue<FileActivity> _recent = new();
    private readonly ConcurrentQueue<FileActivity> _toLog = new();
    private readonly object _stateLock = new();

    private Timer? _flushTimer;
    private Timer? _autoBackupTimer;
    private int _autoBackupRunning;
    private bool _disposed;

    public ProtectionService()
    {
        Settings = new SettingsService();
        Repo = new ProtectionRepository();
        Classifier = new ThreatClassifier();
        Honeypots = new HoneypotService(Repo);
        Controller = new ProcessController();
        Behavior = new ProcessBehaviorMonitor(() => Settings.Current, Controller);
        Detection = new DetectionEngine(() => Settings.Current, Classifier);
        Files = new FileActivityMonitor(Honeypots.IsHoneypot, IsIgnored);
        CommandLine = new CommandLineMonitor(() => Settings.Current);
        Persistence = new PersistenceMonitor();
        ServiceWatcher = new SecurityServiceWatcher();
        Quarantine = new QuarantineService(Repo);
        Network = new NetworkIsolationService();
        Evidence = new EvidenceService();
        Cfa = new ControlledFolderAccessService();
        Recovery = new RecoveryService(Settings, Repo, Honeypots);
        Integrity = new IntegrityService(Repo, Settings, Honeypots);
        Reports = new ReportService(Settings, Repo, Honeypots, Recovery, Integrity, Network);
        Orchestrator = new ResponseOrchestrator(Settings, Repo, Controller, Quarantine, Network, Evidence, Cfa,
            Behavior, RecentActivity);

        Files.ActivityObserved += OnActivity;
        Files.WatcherError += OnWatcherError;
        Detection.Detected += OnDetected;
        CommandLine.Detected += OnDetected;
        Persistence.Detected += OnDetected;
        ServiceWatcher.Detected += OnDetected;
        Recovery.Detected += OnDetected;
    }

    public SettingsService Settings { get; }
    public ProtectionRepository Repo { get; }
    public ThreatClassifier Classifier { get; }
    public HoneypotService Honeypots { get; }
    public ProcessController Controller { get; }
    public ProcessBehaviorMonitor Behavior { get; }
    public DetectionEngine Detection { get; }
    public FileActivityMonitor Files { get; }
    public CommandLineMonitor CommandLine { get; }
    public PersistenceMonitor Persistence { get; }
    public SecurityServiceWatcher ServiceWatcher { get; }
    public QuarantineService Quarantine { get; }
    public NetworkIsolationService Network { get; }
    public EvidenceService Evidence { get; }
    public ControlledFolderAccessService Cfa { get; }
    public RecoveryService Recovery { get; }
    public IntegrityService Integrity { get; }
    public ReportService Reports { get; }
    public ResponseOrchestrator Orchestrator { get; }

    public bool IsRunning => Files.IsRunning;

    /// <summary>Raised when protection is switched on or off.</summary>
    public event Action? StateChanged;

    /// <summary>Raised for problems the user should hear about (watcher overflow, a failed response, and so on).</summary>
    public event Action<string>? Problem;

    // ------------------------------------------------------------------
    // Start and stop
    // ------------------------------------------------------------------

    /// <summary>Loads settings, opens the database and, if protection was on last time, turns it back on.</summary>
    public void Initialize()
    {
        Settings.Load();
        Database.Initialize();
        Classifier.Load(AppPaths.ModelFile);
        Honeypots.Load();
        if (Settings.Current.ProtectionEnabled) Start();
    }

    public (bool Ok, string Message) Start()
    {
        var notes = new List<string>();
        lock (_stateLock)
        {
            if (_disposed) return (false, "WinShield is shutting down.");
            if (IsRunning) return (true, "Protection is already on.");

            var settings = Settings.Current;
            var folders = settings.ProtectedFolders.Where(Directory.Exists).ToList();
            if (folders.Count == 0)
                return (false, "Add at least one protected folder that exists, then turn protection on.");

            if (settings.HoneypotsEnabled)
            {
                try { Honeypots.Deploy(folders); }
                catch (Exception ex) { notes.Add("Decoy files could not be created: " + ex.Message); }
            }

            Detection.Reset();
            Files.Start(folders);
            Behavior.Start();
            if (!CommandLine.Start())
                notes.Add("Command-line monitoring is off (it needs administrator rights).");
            Persistence.Start();
            ServiceWatcher.Start();
            Recovery.StartGuard();

            _flushTimer = new Timer(_ => FlushLog(), null, TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(2));
            _autoBackupTimer = new Timer(_ => MaybeCreateAutomaticPoint(), null, TimeSpan.FromSeconds(45), TimeSpan.FromMinutes(10));

            settings.ProtectionEnabled = true;
            Settings.Save();
        }

        StateChanged?.Invoke();
        return (true, notes.Count == 0 ? "Protection is on." : "Protection is on. " + string.Join(" ", notes));
    }

    /// <summary>Turns protection off. With <paramref name="remember"/> the choice is kept for the next start.</summary>
    public void Stop(bool remember = true)
    {
        lock (_stateLock)
        {
            _flushTimer?.Dispose();
            _flushTimer = null;
            _autoBackupTimer?.Dispose();
            _autoBackupTimer = null;

            Files.Stop();
            Behavior.Stop();
            CommandLine.Stop();
            Persistence.Stop();
            ServiceWatcher.Stop();
            Recovery.StopGuard();
            FlushLog();

            if (remember)
            {
                Settings.Current.ProtectionEnabled = false;
                try { Settings.Save(); } catch (IOException) { }
            }
        }
        StateChanged?.Invoke();
    }

    // ------------------------------------------------------------------
    // Event plumbing
    // ------------------------------------------------------------------

    private bool IsIgnored(string path) =>
        AppPaths.IsInternal(path) ||
        AppPaths.IsUnder(path, Settings.Current.BackupFolder) ||
        Recovery.SuppressDetection;

    private void OnActivity(FileActivity activity)
    {
        _recent.Enqueue(activity);
        while (_recent.Count > RecentActivityLimit && _recent.TryDequeue(out _)) { }

        if (_toLog.Count < 20_000) _toLog.Enqueue(activity);

        Detection.Process(activity);
    }

    private void OnWatcherError(string message)
    {
        // The operating system dropped events (buffer overflow). Treat the gap as suspicious rather than ignoring it.
        Detection.ReportOverflow(message);
        Problem?.Invoke(message);
    }

    private void OnDetected(DetectionResult detection)
    {
        _ = HandleDetectionAsync(detection);
    }

    private async Task HandleDetectionAsync(DetectionResult detection)
    {
        try
        {
            await Orchestrator.HandleAsync(detection);
        }
        catch (Exception ex)
        {
            Problem?.Invoke($"Could not respond to \"{detection.Title}\": {ex.Message}");
        }
    }

    private void FlushLog()
    {
        if (_toLog.IsEmpty) return;
        var batch = new List<FileActivity>();
        while (batch.Count < 2000 && _toLog.TryDequeue(out var a)) batch.Add(a);
        try
        {
            Repo.LogFileEvents(batch);
        }
        catch (Exception)
        {
            // The activity log is a convenience; losing a batch must never stop protection.
        }
    }

    /// <summary>The most recent file events, oldest first. Used for evidence and the live feed.</summary>
    public IReadOnlyList<FileActivity> RecentActivity() => _recent.ToArray();

    // ------------------------------------------------------------------
    // Automatic recovery points
    // ------------------------------------------------------------------

    private void MaybeCreateAutomaticPoint()
    {
        var hours = Settings.Current.AutoRecoveryPointHours;
        if (hours <= 0 || !IsRunning || Orchestrator.EmergencyActive) return;
        if (Interlocked.Exchange(ref _autoBackupRunning, 1) == 1) return;

        _ = Task.Run(() =>
        {
            try
            {
                // Never take a "good" backup while something serious is open: it could contain encrypted files.
                var openSerious = Repo.GetIncidents(20).Any(i => i.Status is "Open" or "Contained" && i.Severity >= Severity.High);
                if (openSerious) return;

                var age = Recovery.AgeOfNewestGoodPoint();
                if (age is null || age.Value.TotalHours >= hours)
                    Recovery.CreatePoint("Automatic", tainted: false);
            }
            catch (Exception ex)
            {
                Problem?.Invoke("Automatic recovery point failed: " + ex.Message);
            }
            finally
            {
                Interlocked.Exchange(ref _autoBackupRunning, 0);
            }
        });
    }

    public void Dispose()
    {
        lock (_stateLock) _disposed = true;
        Stop(remember: false);
        Detection.Dispose();
        Files.Dispose();
        Behavior.Dispose();
        CommandLine.Dispose();
        Persistence.Dispose();
        ServiceWatcher.Dispose();
        Recovery.Dispose();
    }
}
