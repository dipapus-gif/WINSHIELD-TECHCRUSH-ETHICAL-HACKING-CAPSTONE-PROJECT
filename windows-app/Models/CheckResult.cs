namespace WinShield.Models;

public enum CheckStatus
{
    Pass,
    Warning,
    Fail,
    Info
}

/// <summary>The outcome of a single security check.</summary>
public sealed record CheckResult(
    string Id,
    string Title,
    CheckStatus Status,
    string Detail,
    string Recommendation);
