using WinShield.Models;

namespace WinShield.Services;

public sealed record ScanSummary(int Score, int PassCount, int WarnCount, int FailCount);

/// <summary>Runs every security check and turns the results into a 0-100 score.</summary>
public sealed class ScanEngine
{
    private readonly (string Id, string Title, Func<CheckResult> Run)[] _checks =
    {
        ("defender_realtime", "Microsoft Defender real-time protection", SecurityChecks.Defender),
        ("firewall_profiles", "Windows Firewall profiles", SecurityChecks.Firewall),
        ("uac_enabled", "User Account Control (UAC)", SecurityChecks.Uac),
        ("windows_update", "Windows Update service", SecurityChecks.WindowsUpdate),
        ("smartscreen", "SmartScreen app reputation checks", SecurityChecks.SmartScreen),
        ("remote_desktop", "Remote Desktop", SecurityChecks.RemoteDesktop),
        ("smb1", "SMBv1 file sharing protocol", SecurityChecks.Smb1),
        ("autologon", "Automatic sign-in", SecurityChecks.AutoLogon),
        ("secure_boot", "Secure Boot", SecurityChecks.SecureBoot),
        ("startup_items", "Programs that start with Windows", SecurityChecks.StartupItems),
    };

    public List<CheckResult> Run()
    {
        var results = new List<CheckResult>(_checks.Length);
        foreach (var (id, title, run) in _checks)
        {
            try
            {
                results.Add(run());
            }
            catch (Exception ex)
            {
                // One broken check (for example a locked-down registry key) must not stop the scan.
                results.Add(new CheckResult(id, title, CheckStatus.Info,
                    $"This check could not run: {ex.Message}",
                    "Try running WinShield as administrator."));
            }
        }
        return results;
    }

    /// <summary>Pass = 1 point, Warning = half a point, Fail = 0. Info results are not scored.</summary>
    public static ScanSummary Summarize(IReadOnlyCollection<CheckResult> results)
    {
        var pass = results.Count(r => r.Status == CheckStatus.Pass);
        var warn = results.Count(r => r.Status == CheckStatus.Warning);
        var fail = results.Count(r => r.Status == CheckStatus.Fail);

        var scored = pass + warn + fail;
        var score = scored == 0 ? 100 : (int)Math.Round((pass + warn * 0.5) / scored * 100);
        return new ScanSummary(score, pass, warn, fail);
    }
}
