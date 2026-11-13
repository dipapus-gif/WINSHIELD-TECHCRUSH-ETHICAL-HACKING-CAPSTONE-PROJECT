namespace WinShield.Models;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum FileEventKind
{
    Created,
    Modified,
    Deleted,
    Renamed
}

/// <summary>One observed file-system event inside a protected folder.</summary>
public sealed record FileActivity(
    DateTime TimeUtc,
    FileEventKind Kind,
    string FilePath,
    string? OldPath,
    long Size,
    double Entropy,
    bool IsHoneypot)
{
    public string Extension => Path.GetExtension(FilePath).ToLowerInvariant();
    public string? OldExtension => OldPath is null ? null : Path.GetExtension(OldPath).ToLowerInvariant();
    public string FileName => Path.GetFileName(FilePath);
    public DateTime TimeLocal => TimeUtc.ToLocalTime();
    public string EntropyText => Entropy < 0 ? "" : Entropy.ToString("0.00");
    public string KindText => IsHoneypot ? Kind + " (decoy)" : Kind.ToString();
}

/// <summary>Something the detectors consider a threat. The response engine turns it into an incident.</summary>
public sealed class DetectionResult
{
    public DateTime TimeUtc { get; init; } = DateTime.UtcNow;
    public Severity Severity { get; init; }
    public double Score { get; init; }
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public List<string> RuleIds { get; init; } = new();
    public List<string> AffectedFiles { get; init; } = new();
    public Dictionary<string, double> Features { get; init; } = new();

    /// <summary>True when the evidence is strong enough that acting on the responsible process is reasonable.</summary>
    public bool SuggestsProcessAction { get; init; }

    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessPath { get; set; }

    /// <summary>How the process was identified: High (holds the file), Medium (heaviest writer), Low, or Unknown.</summary>
    public string Attribution { get; set; } = "Unknown";
}

public sealed class Incident
{
    public long Id { get; set; }
    public DateTime TimeUtc { get; set; }
    public Severity Severity { get; set; }
    public double Score { get; set; }
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";
    public string RuleIds { get; set; } = "";
    public int? ProcessId { get; set; }
    public string? ProcessName { get; set; }
    public string? ProcessPath { get; set; }
    public string Attribution { get; set; } = "Unknown";
    public string Status { get; set; } = "Open";
    public DateTime? ResolvedUtc { get; set; }
    public string? EvidencePath { get; set; }
    public int AffectedCount { get; set; }

    public DateTime TimeLocal => TimeUtc.ToLocalTime();
    public string ProcessText => ProcessName is null ? "(not identified)" : $"{ProcessName} (PID {ProcessId})";
}

public sealed class IncidentAction
{
    public long IncidentId { get; set; }
    public DateTime TimeUtc { get; set; }
    public string Action { get; set; } = "";
    public string Detail { get; set; } = "";
    public bool Success { get; set; } = true;

    public DateTime TimeLocal => TimeUtc.ToLocalTime();
    public string Result => Success ? "OK" : "Failed";
}

public sealed class SuspiciousProcess
{
    public int Pid { get; set; }
    public string Name { get; set; } = "";
    public string? Path { get; set; }
    public double WriteMBps { get; set; }
    public double CpuPercent { get; set; }
    public double Score { get; set; }
    public string Reasons { get; set; } = "";
    public bool IsSuspended { get; set; }

    public string WriteText => WriteMBps.ToString("0.0") + " MB/s";
    public string CpuText => CpuPercent.ToString("0") + "%";
    public string StateText => IsSuspended ? "Suspended" : "Running";
}

public sealed record BaselineEntry(string FilePath, string Sha256, long Size, DateTime LastWriteUtc);

public sealed class IntegrityChange
{
    public string Kind { get; set; } = "";       // Modified, Deleted, New, Renamed
    public string FilePath { get; set; } = "";
    public string? PreviousPath { get; set; }
    public string? OldSha256 { get; set; }
    public string? NewSha256 { get; set; }

    public string Detail => Kind == "Renamed" ? $"from {PreviousPath}" : "";
}

public sealed class HoneypotFile
{
    public string FilePath { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string Folder { get; set; } = "";
    public DateTime CreatedUtc { get; set; }
    public string Status { get; set; } = "";
    public DateTime CreatedLocal => CreatedUtc.ToLocalTime();
}

public sealed class QuarantineItem
{
    public long Id { get; set; }
    public string OriginalPath { get; set; } = "";
    public string QuarantinePath { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public DateTime TimeUtc { get; set; }
    public long? IncidentId { get; set; }
    public string Reason { get; set; } = "";
    public bool Restored { get; set; }

    public DateTime TimeLocal => TimeUtc.ToLocalTime();
    public string StateText => Restored ? "Restored" : "Quarantined";
}

public sealed class RecoveryPoint
{
    public long Id { get; set; }
    public DateTime TimeUtc { get; set; }
    public string Label { get; set; } = "";
    public string Folder { get; set; } = "";
    public int FileCount { get; set; }
    public long TotalBytes { get; set; }
    public bool Verified { get; set; }

    public DateTime TimeLocal => TimeUtc.ToLocalTime();
    public string SizeText => (TotalBytes / 1048576.0).ToString("0.0") + " MB";
    public string VerifiedText => Verified ? "Verified" : "Not verified";
}

public sealed record ProtectionStats(
    int TotalIncidents,
    int OpenIncidents,
    int CriticalIncidents30d,
    int HighIncidents30d,
    int FileEvents24h);

public sealed record LiveMetrics(int Modified, int Renamed, int Deleted, int HighEntropy, double Score)
{
    public static LiveMetrics Empty { get; } = new(0, 0, 0, 0, 0);
}
