using System.Text.Json;
using Microsoft.Win32;
using WinShield.Core;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Detects new ways of starting a program automatically (Run keys, Startup folders, scheduled tasks and
/// services that run from user-writable folders) by comparing against a saved baseline.
/// </summary>
public sealed class PersistenceMonitor : IDisposable
{
    private static readonly string[] RiskyKeywords =
        { "powershell", "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "cmd.exe /c", "cmd /c", "-enc" };

    private readonly object _lock = new();
    private HashSet<string> _baseline = new(StringComparer.OrdinalIgnoreCase);
    private Timer? _timer;

    public event Action<DetectionResult>? Detected;

    public void Start()
    {
        Stop();
        LoadOrCreateBaseline();
        _timer = new Timer(_ => Poll(), null, 5000, 45000);
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    private void LoadOrCreateBaseline()
    {
        try
        {
            if (File.Exists(AppPaths.PersistenceBaseline))
            {
                var keys = JsonSerializer.Deserialize<List<string>>(File.ReadAllText(AppPaths.PersistenceBaseline));
                if (keys is not null)
                {
                    lock (_lock) _baseline = new HashSet<string>(keys, StringComparer.OrdinalIgnoreCase);
                    return;
                }
            }
        }
        catch
        {
            // fall through and rebuild
        }

        var snapshot = Snapshot();
        lock (_lock) _baseline = new HashSet<string>(snapshot.Keys, StringComparer.OrdinalIgnoreCase);
        SaveBaseline();
    }

    private void SaveBaseline()
    {
        try
        {
            AppPaths.EnsureAll();
            List<string> keys;
            lock (_lock) keys = _baseline.ToList();
            File.WriteAllText(AppPaths.PersistenceBaseline, JsonSerializer.Serialize(keys));
        }
        catch
        {
            // non-fatal
        }
    }

    private void Poll()
    {
        try
        {
            var snapshot = Snapshot();
            List<KeyValuePair<string, string>> added;
            lock (_lock) added = snapshot.Where(kv => !_baseline.Contains(kv.Key)).ToList();
            if (added.Count == 0) return;

            var risky = added.Where(kv => IsRisky(kv.Value)).ToList();
            var severity = risky.Count > 0 ? Severity.High : Severity.Medium;
            var shown = string.Join("; ", added.Take(5).Select(kv => $"{Describe(kv.Key)} = {kv.Value}"));
            if (added.Count > 5) shown += $" (+{added.Count - 5} more)";

            lock (_lock)
            {
                foreach (var kv in added) _baseline.Add(kv.Key);
            }
            SaveBaseline();

            Detected?.Invoke(new DetectionResult
            {
                Severity = severity,
                Score = severity == Severity.High ? 70 : 40,
                Title = "New startup / persistence entry",
                Description = "Something added a way to run automatically: " + shown +
                              (risky.Count > 0 ? ". At least one entry runs from a user-writable folder or uses a script host." : "."),
                RuleIds = { "P-NEW-PERSISTENCE" },
                AffectedFiles = added.Select(kv => kv.Value).Take(20).ToList()
            });
        }
        catch
        {
            // best effort
        }
    }

    private static string Describe(string key) => key.Split('|')[0] switch
    {
        "run" => "Run key",
        "startup" => "Startup folder",
        "task" => "Scheduled task",
        "svc" => "Service",
        _ => "Entry"
    };

    private static bool IsRisky(string value)
    {
        if (ProcessSafety.IsUserWritableLocation(ExtractPath(value))) return true;
        return RiskyKeywords.Any(k => value.Contains(k, StringComparison.OrdinalIgnoreCase));
    }

    private static string ExtractPath(string value)
    {
        var v = Environment.ExpandEnvironmentVariables(value.Trim());
        if (v.StartsWith('"'))
        {
            var end = v.IndexOf('"', 1);
            return end > 1 ? v[1..end] : v.Trim('"');
        }
        var exe = v.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        return exe > 0 ? v[..(exe + 4)] : v;
    }

    private static Dictionary<string, string> Snapshot()
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        void ReadRun(RegistryHive hive, RegistryView view, string subKey, string label)
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(hive, view);
                using var key = baseKey.OpenSubKey(subKey);
                if (key is null) return;
                foreach (var name in key.GetValueNames())
                    result[$"run|{label}|{subKey}|{name}"] = key.GetValue(name)?.ToString() ?? "";
            }
            catch
            {
                // key not readable
            }
        }

        foreach (var sub in new[]
                 {
                     @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                     @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                 })
        {
            ReadRun(RegistryHive.LocalMachine, RegistryView.Registry64, sub, "HKLM");
            ReadRun(RegistryHive.LocalMachine, RegistryView.Registry32, sub, "HKLM32");
            ReadRun(RegistryHive.CurrentUser, RegistryView.Registry64, sub, "HKCU");
        }

        foreach (var dir in new[]
                 {
                     Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                     Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup)
                 })
        {
            try
            {
                if (!Directory.Exists(dir)) continue;
                foreach (var file in Directory.EnumerateFiles(dir))
                    if (!file.EndsWith("desktop.ini", StringComparison.OrdinalIgnoreCase))
                        result[$"startup|{file}"] = file;
            }
            catch
            {
                // folder not readable
            }
        }

        try
        {
            var tasks = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
            if (Directory.Exists(tasks))
            {
                foreach (var file in Directory.EnumerateFiles(tasks, "*", SearchOption.AllDirectories))
                    result[$"task|{file}"] = file;
            }
        }
        catch
        {
            // tasks folder needs rights on some systems
        }

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var services = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (services is not null)
            {
                foreach (var name in services.GetSubKeyNames())
                {
                    using var svc = services.OpenSubKey(name);
                    var image = svc?.GetValue("ImagePath")?.ToString();
                    if (!string.IsNullOrWhiteSpace(image) && ProcessSafety.IsUserWritableLocation(ExtractPath(image)))
                        result[$"svc|{name}"] = image;
                }
            }
        }
        catch
        {
            // services key not readable
        }

        return result;
    }

    public void Dispose() => Stop();
}
