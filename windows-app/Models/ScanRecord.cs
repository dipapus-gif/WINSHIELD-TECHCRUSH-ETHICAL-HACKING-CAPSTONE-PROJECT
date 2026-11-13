namespace WinShield.Models;

/// <summary>A saved scan: the summary row stored in the scans table.</summary>
public sealed class ScanRecord
{
    public long Id { get; set; }
    public DateTime StartedUtc { get; set; }
    public string MachineName { get; set; } = string.Empty;
    public int Score { get; set; }
    public int PassCount { get; set; }
    public int WarnCount { get; set; }
    public int FailCount { get; set; }

    public DateTime StartedLocal => StartedUtc.ToLocalTime();
}
