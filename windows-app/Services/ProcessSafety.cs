using WinShield.Core;

namespace WinShield.Services;

public sealed record ProcessRef(int Pid, string Name, string? Path, string Attribution);

/// <summary>Guard rails: decides which processes WinShield must never suspend, kill or quarantine.</summary>
public static class ProcessSafety
{
    private static readonly HashSet<string> CoreWindowsProcesses = new(StringComparer.OrdinalIgnoreCase)
    {
        "system", "idle", "registry", "smss", "csrss", "wininit", "winlogon", "services", "lsass", "lsm",
        "svchost", "dwm", "fontdrvhost", "sihost", "taskhostw", "spoolsv", "explorer", "msmpeng", "nissrv",
        "securityhealthservice", "wudfhost", "audiodg", "conhost", "ctfmon", "runtimebroker", "searchindexer",
        "trustedinstaller", "tiworker", "vmmem", "memory compression"
    };

    private static readonly HashSet<string> ScriptHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta", "wt", "windowsterminal", "conhost", "explorer"
    };

    public static string NormalizeName(string name) =>
        name.Trim().ToLowerInvariant().Replace(".exe", "");

    /// <summary>Returns the reason a process must not be acted on, or null when action is allowed.</summary>
    public static string? WhyProtected(int pid, string name, string? path, IEnumerable<string> trusted)
    {
        if (pid <= 4) return "it is a core system process";
        if (pid == Environment.ProcessId) return "it is WinShield itself";

        var n = NormalizeName(name);
        if (CoreWindowsProcesses.Contains(n)) return $"{name} is a core Windows process";
        if (trusted.Any(t => string.Equals(t, n, StringComparison.OrdinalIgnoreCase)))
            return $"{name} is on your trusted list";

        if (path is not null)
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (AppPaths.IsUnder(path, windows)) return "it runs from the Windows folder";
        }
        return null;
    }

    public static bool IsScriptHost(string name) => ScriptHosts.Contains(NormalizeName(name));

    /// <summary>Temp, AppData, Downloads, Public and ProgramData are where malware usually runs from.</summary>
    public static bool IsUserWritableLocation(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;

        var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        var candidates = new[]
        {
            Path.GetTempPath(),
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            Path.Combine(profile, "Downloads"),
            Path.Combine(profile, "Desktop"),
            Environment.GetEnvironmentVariable("PUBLIC") ?? "",
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        };

        return candidates.Any(c => !string.IsNullOrWhiteSpace(c) && AppPaths.IsUnder(path, c));
    }
}
