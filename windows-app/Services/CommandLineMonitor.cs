using System.Diagnostics;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using WinShield.Core;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Watches new processes (through WMI) for command lines that attack recovery and security features:
/// deleting shadow copies or backups, disabling Defender or the firewall, clearing logs. Needs administrator rights.
/// </summary>
public sealed class CommandLineMonitor : IDisposable
{
    private sealed record CommandRule(string Id, string Title, Severity Severity, Regex Pattern, string Why);

    private static Regex Rx(string pattern) =>
        new(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly CommandRule[] Rules =
    {
        new("C-SHADOW-DELETE", "Shadow copy deletion attempt", Severity.Critical,
            Rx(@"vssadmin(\.exe)?\s+(delete\s+shadows|resize\s+shadowstorage)|wmic(\.exe)?\s+.*shadowcopy.*delete|" +
               @"(get-wmiobject|get-ciminstance|gwmi)\s+.*win32_shadowcopy.*(delete|remove)|win32_shadowcopy.*\.delete\(\)"),
            "Ransomware deletes Volume Shadow Copies so files cannot be restored."),

        new("C-BACKUP-DELETE", "Backup deletion attempt", Severity.Critical,
            Rx(@"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)"),
            "Ransomware deletes Windows backup catalogs to prevent recovery."),

        new("C-RECOVERY-OFF", "Windows recovery disabled", Severity.High,
            Rx(@"bcdedit(\.exe)?\s+.*(recoveryenabled\s+(no|off)|bootstatuspolicy\s+ignoreallfailures)"),
            "Turning off boot recovery stops Windows from offering repair after an attack."),

        new("C-LOG-CLEAR", "Event log clearing", Severity.High,
            Rx(@"wevtutil(\.exe)?\s+(cl|clear-log)\b|clear-eventlog"),
            "Clearing event logs hides evidence of an intrusion."),

        new("C-DEFENDER-OFF", "Attempt to weaken Microsoft Defender", Severity.High,
            Rx(@"set-mppreference\s+.*-disable(realtimemonitoring|behaviormonitoring|ioavprotection|scriptscanning|blockatfirstseen)\s+(\$true|1)|" +
               @"add-mppreference\s+.*-exclusion(path|extension|process)|" +
               @"(sc(\.exe)?|net)\s+(stop|config)\s+(windefend|sense|wdnissvc|wscsvc)|" +
               @"reg(\.exe)?\s+add\s+.*windows defender.*(disableantispyware|disablerealtimemonitoring)"),
            "Disabling antivirus protection is a common first step before encryption."),

        new("C-SERVICE-STOP", "Attempt to stop backup or database services", Severity.Medium,
            Rx(@"taskkill(\.exe)?\s+.*(msmpeng|msseces|mbam|sqlservr|veeam)|(net|sc)(\.exe)?\s+stop\s+(vss|sdrsvc|veeam\w*|backup\w*)"),
            "Ransomware stops backup and database services so their files can be encrypted."),

        new("C-FIREWALL-OFF", "Firewall disabled from the command line", Severity.High,
            Rx(@"netsh(\.exe)?\s+advfirewall\s+set\s+\w+\s+state\s+off|set-netfirewallprofile\s+.*-enabled\s+false"),
            "Turning off the firewall exposes the PC to the network."),

        new("C-FREE-SPACE-WIPE", "Free-space wipe (cipher /w)", Severity.Medium,
            Rx(@"cipher(\.exe)?\s+/w"),
            "Wiping free space makes deleted original files unrecoverable after encryption.")
    };

    private static readonly Regex EncodedPattern = new(
        @"-e(nc(odedcommand)?)?\s+(?<b64>[A-Za-z0-9+/=]{20,})", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private readonly Func<AppSettings> _settings;
    private readonly Dictionary<string, DateTime> _recent = new();
    private ManagementEventWatcher? _watcher;

    public CommandLineMonitor(Func<AppSettings> settings) => _settings = settings;

    public event Action<DetectionResult>? Detected;

    public bool IsRunning => _watcher is not null;
    public string Status { get; private set; } = "Stopped";

    public bool Start()
    {
        Stop();
        try
        {
            var query = new WqlEventQuery("__InstanceCreationEvent", TimeSpan.FromSeconds(1),
                "TargetInstance ISA 'Win32_Process'");
            _watcher = new ManagementEventWatcher(query);
            _watcher.EventArrived += OnProcessStarted;
            _watcher.Start();
            Status = "Running";
            return true;
        }
        catch (Exception ex)
        {
            Status = AdminHelper.IsAdministrator
                ? $"Unavailable: {ex.Message}"
                : "Unavailable: start WinShield as administrator to watch process command lines.";
            _watcher?.Dispose();
            _watcher = null;
            return false;
        }
    }

    public void Stop()
    {
        try { _watcher?.Stop(); } catch { /* ignore */ }
        _watcher?.Dispose();
        _watcher = null;
        Status = "Stopped";
    }

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            if (e.NewEvent["TargetInstance"] is not ManagementBaseObject target) return;
            var name = target["Name"] as string ?? "";
            var commandLine = target["CommandLine"] as string;
            var pid = Convert.ToInt32(target["ProcessId"]);
            var parentPid = Convert.ToInt32(target["ParentProcessId"]);
            Analyze(name, commandLine, pid, parentPid);
        }
        catch
        {
            // WMI events can race with process exit
        }
    }

    internal void Analyze(string name, string? commandLine, int pid, int parentPid)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return;
        if (pid == Environment.ProcessId) return;

        var text = commandLine;
        var encoded = EncodedPattern.Match(commandLine);
        if (encoded.Success)
        {
            try
            {
                text += " " + Encoding.Unicode.GetString(Convert.FromBase64String(encoded.Groups["b64"].Value));
            }
            catch
            {
                // not valid base64: analyse the raw command line only
            }
        }

        foreach (var rule in Rules)
        {
            if (!rule.Pattern.IsMatch(text)) continue;

            var key = $"{rule.Id}|{parentPid}";
            var now = DateTime.UtcNow;
            if (_recent.TryGetValue(key, out var last) && (now - last).TotalSeconds < 30) continue;
            _recent[key] = now;
            if (_recent.Count > 500) _recent.Clear();

            string parentName = "unknown";
            string? parentPath = null;
            try
            {
                using var parent = Process.GetProcessById(parentPid);
                parentName = parent.ProcessName;
                parentPath = Win32.TryGetProcessPath(parentPid);
            }
            catch
            {
                // parent already exited
            }

            var shown = commandLine.Length > 300 ? commandLine[..300] + "..." : commandLine;
            var trusted = _settings().TrustedProcesses;

            // Only recommend acting on the launcher when it is not a shell/script host and runs from a risky folder.
            var actionable = rule.Severity >= Severity.High
                             && parentPath is not null
                             && ProcessSafety.IsUserWritableLocation(parentPath)
                             && !ProcessSafety.IsScriptHost(parentName)
                             && ProcessSafety.WhyProtected(parentPid, parentName, parentPath, trusted) is null;

            Detected?.Invoke(new DetectionResult
            {
                Severity = rule.Severity,
                Score = rule.Severity == Severity.Critical ? 95 : rule.Severity == Severity.High ? 75 : 45,
                Title = rule.Title,
                Description = $"{rule.Why} Command: {shown} (started by {parentName}, PID {parentPid}).",
                RuleIds = { rule.Id },
                SuggestsProcessAction = actionable,
                ProcessId = parentPid > 0 ? parentPid : null,
                ProcessName = parentName,
                ProcessPath = parentPath,
                Attribution = parentPath is null ? "Low" : "Medium"
            });
            return;
        }
    }

    public void Dispose() => Stop();
}
