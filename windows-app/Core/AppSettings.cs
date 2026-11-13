using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinShield.Core;

public enum ResponseMode
{
    /// <summary>Detect and alert only. Never touches processes or the network.</summary>
    MonitorOnly,

    /// <summary>Ask the user before any disruptive action (default).</summary>
    AskFirst,

    /// <summary>Act automatically on Critical threats and on High threats with an identified process.</summary>
    AutoContain
}

public sealed class AppSettings
{
    public List<string> ProtectedFolders { get; set; } = new();
    public bool ProtectionEnabled { get; set; }
    public ResponseMode ResponseMode { get; set; } = ResponseMode.AskFirst;
    public bool AutoIsolateOnCritical { get; set; }
    public bool HoneypotsEnabled { get; set; } = true;

    // Detection thresholds (counted over a sliding window of distinct files).
    public int WindowSeconds { get; set; } = 10;
    public int MassModifyThreshold { get; set; } = 40;
    public int MassRenameThreshold { get; set; } = 15;
    public int MassDeleteThreshold { get; set; } = 40;
    public int SuspiciousExtThreshold { get; set; } = 3;
    public double HighEntropyThreshold { get; set; } = 7.5;
    public int HighEntropyFileCount { get; set; } = 8;
    public double SuspiciousWriteMBps { get; set; } = 30;

    // Backups
    public string BackupFolder { get; set; } = AppPaths.DefaultBackups;
    public int MaxBackupFileMB { get; set; } = 100;
    public int MaxBackupTotalGB { get; set; } = 10;
    public int MaxRecoveryPoints { get; set; } = 5;

    /// <summary>Create a recovery point automatically when the newest one is older than this many hours. 0 turns it off.</summary>
    public int AutoRecoveryPointHours { get; set; } = 24;

    /// <summary>Process names (without .exe) that are never suspended, killed or quarantined automatically.</summary>
    public List<string> TrustedProcesses { get; set; } = new()
    {
        "explorer", "onedrive", "dropbox", "googledrivefs", "code", "devenv",
        "msedge", "chrome", "firefox", "searchindexer", "msmpeng", "winshield"
    };
}

public sealed class SettingsService
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly object _lock = new();

    public AppSettings Current { get; private set; } = new();

    public event Action? Changed;

    public void Load()
    {
        AppPaths.EnsureAll();
        try
        {
            if (File.Exists(AppPaths.SettingsFile))
            {
                var json = File.ReadAllText(AppPaths.SettingsFile);
                Current = JsonSerializer.Deserialize<AppSettings>(json, Options) ?? new AppSettings();
            }
        }
        catch
        {
            Current = new AppSettings();
        }

        if (Current.ProtectedFolders.Count == 0)
            Current.ProtectedFolders.AddRange(DefaultFolders());

        Normalize(Current);
    }

    public void Save()
    {
        lock (_lock)
        {
            Normalize(Current);
            AppPaths.EnsureAll();
            var tmp = AppPaths.SettingsFile + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(Current, Options));
            File.Move(tmp, AppPaths.SettingsFile, overwrite: true);
        }
        Changed?.Invoke();
    }

    public static IEnumerable<string> DefaultFolders()
    {
        var candidates = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)
        };
        return candidates.Where(p => !string.IsNullOrWhiteSpace(p) && Directory.Exists(p)).Distinct();
    }

    private static void Normalize(AppSettings s)
    {
        s.WindowSeconds = Math.Clamp(s.WindowSeconds, 3, 120);
        s.MassModifyThreshold = Math.Clamp(s.MassModifyThreshold, 5, 5000);
        s.MassRenameThreshold = Math.Clamp(s.MassRenameThreshold, 3, 5000);
        s.MassDeleteThreshold = Math.Clamp(s.MassDeleteThreshold, 5, 5000);
        s.SuspiciousExtThreshold = Math.Clamp(s.SuspiciousExtThreshold, 1, 100);
        s.HighEntropyThreshold = Math.Clamp(s.HighEntropyThreshold, 6.0, 8.0);
        s.HighEntropyFileCount = Math.Clamp(s.HighEntropyFileCount, 2, 1000);
        s.SuspiciousWriteMBps = Math.Clamp(s.SuspiciousWriteMBps, 5, 1000);
        s.MaxBackupFileMB = Math.Clamp(s.MaxBackupFileMB, 1, 4096);
        s.MaxBackupTotalGB = Math.Clamp(s.MaxBackupTotalGB, 1, 2048);
        s.MaxRecoveryPoints = Math.Clamp(s.MaxRecoveryPoints, 1, 50);
        s.AutoRecoveryPointHours = Math.Clamp(s.AutoRecoveryPointHours, 0, 720);
        if (string.IsNullOrWhiteSpace(s.BackupFolder)) s.BackupFolder = AppPaths.DefaultBackups;
        s.ProtectedFolders = s.ProtectedFolders
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p.Trim())
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
        s.TrustedProcesses = s.TrustedProcesses
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => p.Trim().ToLowerInvariant().Replace(".exe", ""))
            .Distinct()
            .ToList();
    }
}
