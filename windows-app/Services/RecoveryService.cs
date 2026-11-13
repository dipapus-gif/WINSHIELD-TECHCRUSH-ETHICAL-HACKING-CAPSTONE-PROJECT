using WinShield.Core;
using WinShield.Data;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Recovery points and restores on top of <see cref="BackupStore"/>, plus a guard that raises an alert when
/// the backup store itself is being deleted (a common ransomware step).
/// </summary>
public sealed class RecoveryService : IDisposable
{
    private readonly SettingsService _settings;
    private readonly ProtectionRepository _repo;
    private readonly HoneypotService _honeypots;
    private readonly object _storeLock = new();

    private BackupStore? _store;
    private string? _storeRoot;
    private FileSystemWatcher? _guard;
    private int _guardDeletes;
    private DateTime _guardWindowUtc = DateTime.MinValue;
    private DateTime _lastAlertUtc = DateTime.MinValue;
    private long _quietUntilTicks;

    public RecoveryService(SettingsService settings, ProtectionRepository repo, HoneypotService honeypots)
    {
        _settings = settings;
        _repo = repo;
        _honeypots = honeypots;
    }

    /// <summary>Raised when the backup store is being deleted or tampered with.</summary>
    public event Action<DetectionResult>? Detected;

    /// <summary>
    /// True while a restore is writing into the protected folders (and for a few seconds after), so the detectors
    /// do not mistake the restored files for an attack.
    /// </summary>
    public bool SuppressDetection => Interlocked.Read(ref _quietUntilTicks) > DateTime.UtcNow.Ticks;

    private void QuietFor(TimeSpan span) =>
        Interlocked.Exchange(ref _quietUntilTicks, DateTime.UtcNow.Add(span).Ticks);

    public BackupStore Store
    {
        get
        {
            lock (_storeLock)
            {
                var root = Path.GetFullPath(_settings.Current.BackupFolder);
                if (_store is null || !string.Equals(_storeRoot, root, AppPaths.PathComparison))
                {
                    _store = new BackupStore(root);
                    _storeRoot = root;
                }
                return _store;
            }
        }
    }

    public IReadOnlyList<BackupPoint> List() => Store.ListPoints();

    public BackupPoint CreatePoint(string note, bool tainted, CancellationToken ct = default)
    {
        var s = _settings.Current;
        var point = Store.CreateRecoveryPoint(s.ProtectedFolders, s.MaxBackupFileMB * 1024L * 1024L,
            _honeypots.IsHoneypot, note, tainted, ct);

        _repo.AddRecoveryPoint(new RecoveryPoint
        {
            TimeUtc = point.CreatedUtc,
            Label = string.IsNullOrWhiteSpace(note) ? "Recovery point" : note,
            Folder = point.Id,
            FileCount = point.FileCount,
            TotalBytes = point.TotalBytes
        });

        Prune();
        return point;
    }

    /// <summary>Applies the point-count and total-size limits from the settings.</summary>
    public int Prune()
    {
        var s = _settings.Current;
        var keep = s.MaxRecoveryPoints;
        var capBytes = s.MaxBackupTotalGB * 1024L * 1024L * 1024L;

        // Shared objects are stored once, so the real size is the sum over distinct file contents.
        var points = Store.ListPoints();
        while (keep > 1 && StoreBytes(points.Take(keep)) > capBytes) keep--;

        var removed = Store.Prune(keep);

        var alive = Store.ListPoints().Select(p => p.Id).ToHashSet();
        foreach (var row in _repo.GetRecoveryPoints().Where(r => !alive.Contains(r.Folder)))
            _repo.RemoveRecoveryPoint(row.Id);
        return removed;
    }

    private static long StoreBytes(IEnumerable<BackupPoint> points) =>
        points.SelectMany(p => p.Files).GroupBy(f => f.Sha256).Sum(g => g.First().Size);

    /// <summary>Re-hashes the stored files behind a recovery point and records the outcome.</summary>
    public (int Checked, List<string> Bad) Verify(string pointId)
    {
        var result = Store.VerifyPoint(pointId);
        var row = _repo.GetRecoveryPoints().FirstOrDefault(r => r.Folder == pointId);
        if (row is not null) _repo.SetRecoveryPointVerified(row.Id, result.Bad.Count == 0);
        return result;
    }

    /// <summary>Restores a recovery point. Every restored file is hashed again and compared with the recorded hash.</summary>
    public RestoreResult Restore(string pointId, string? destination, bool inPlace, CancellationToken ct = default)
    {
        if (inPlace) QuietFor(TimeSpan.FromMinutes(10)); // keep the detectors quiet while files are being put back
        try
        {
            return Store.Restore(pointId, destination, inPlace, ct);
        }
        finally
        {
            if (inPlace) QuietFor(TimeSpan.FromSeconds(8));
        }
    }

    /// <summary>The age of the newest recovery point that was not made during an incident.</summary>
    public TimeSpan? AgeOfNewestGoodPoint()
    {
        var good = Store.ListPoints().FirstOrDefault(p => !p.Tainted);
        return good is null ? null : DateTime.UtcNow - good.CreatedUtc;
    }

    // ------------------------------------------------------------------
    // Backup tamper guard
    // ------------------------------------------------------------------

    public void StartGuard()
    {
        StopGuard();
        try
        {
            var root = Store.Root;
            Directory.CreateDirectory(root);
            _guard = new FileSystemWatcher(root)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName,
                InternalBufferSize = 64 * 1024,
                EnableRaisingEvents = true
            };
            _guard.Deleted += OnGuardEvent;
            _guard.Renamed += (_, e) => OnGuardEvent(this, new FileSystemEventArgs(WatcherChangeTypes.Deleted,
                Path.GetDirectoryName(e.OldFullPath) ?? root, Path.GetFileName(e.OldFullPath)));
        }
        catch (Exception)
        {
            _guard = null; // the backup folder may be on a drive that is not available
        }
    }

    public void StopGuard()
    {
        _guard?.Dispose();
        _guard = null;
    }

    private void OnGuardEvent(object sender, FileSystemEventArgs e)
    {
        BackupStore store;
        try { store = Store; } catch { return; }
        if (store.IsBusy) return; // WinShield's own pruning and restores are not an attack

        var now = DateTime.UtcNow;
        if ((now - _guardWindowUtc).TotalSeconds > 15)
        {
            _guardWindowUtc = now;
            _guardDeletes = 0;
        }
        _guardDeletes++;

        var manifestDeleted = e.FullPath.Contains(Path.DirectorySeparatorChar + "points" + Path.DirectorySeparatorChar, AppPaths.PathComparison)
                              && e.FullPath.EndsWith(".json", AppPaths.PathComparison);
        if (!manifestDeleted && _guardDeletes < 5) return;
        if ((now - _lastAlertUtc).TotalSeconds < 60) return;
        _lastAlertUtc = now;

        Detected?.Invoke(new DetectionResult
        {
            Severity = Severity.High,
            Score = 80,
            Title = "Backup store is being deleted",
            Description = "Files inside the WinShield backup folder were deleted by something other than WinShield. " +
                          "Ransomware often destroys backups before it encrypts.",
            RuleIds = new List<string> { "backup_tamper" },
            AffectedFiles = new List<string> { e.FullPath },
            SuggestsProcessAction = false
        });
    }

    public void Dispose() => StopGuard();
}
