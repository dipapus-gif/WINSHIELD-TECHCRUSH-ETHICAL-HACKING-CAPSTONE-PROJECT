using System.ServiceProcess;
using Microsoft.Win32;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Raises an alert when a protection that was working stops working: Defender real-time protection or service,
/// the firewall, the Volume Shadow Copy service or the Event Log service. Only changes are reported, so a PC
/// that never used Defender does not produce alerts.
/// </summary>
public sealed class SecurityServiceWatcher : IDisposable
{
    private sealed record Probe(string Id, string Title, Func<bool> IsOk);

    private readonly Dictionary<string, bool> _state = new();
    private readonly Probe[] _probes;
    private Timer? _timer;

    public SecurityServiceWatcher()
    {
        _probes = new[]
        {
            new Probe("S-DEFENDER-RT", "Microsoft Defender real-time protection", DefenderRealtimeOn),
            new Probe("S-DEFENDER-SVC", "Microsoft Defender service (WinDefend)", () => ServiceRunning("WinDefend")),
            new Probe("S-FIREWALL", "Windows Firewall", FirewallOn),
            new Probe("S-VSS", "Volume Shadow Copy service", VssNotDisabled),
            new Probe("S-EVENTLOG", "Windows Event Log service", () => ServiceRunning("EventLog"))
        };
    }

    public event Action<DetectionResult>? Detected;

    public void Start()
    {
        Stop();
        _state.Clear();
        _timer = new Timer(_ => Poll(), null, 1000, 20000);
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
    }

    private void Poll()
    {
        foreach (var probe in _probes)
        {
            bool ok;
            try { ok = probe.IsOk(); }
            catch { continue; }

            if (_state.TryGetValue(probe.Id, out var wasOk) && wasOk && !ok)
            {
                Detected?.Invoke(new DetectionResult
                {
                    Severity = Severity.High,
                    Score = 75,
                    Title = $"Protection turned off: {probe.Title}",
                    Description = $"{probe.Title} was working a moment ago and is now stopped or disabled. " +
                                  "Ransomware often disables security tools before it starts encrypting.",
                    RuleIds = { probe.Id }
                });
            }
            _state[probe.Id] = ok;
        }
    }

    private static int? ReadInt(string path, string name)
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = baseKey.OpenSubKey(path);
        return key?.GetValue(name) as int?;
    }

    private static bool DefenderRealtimeOn()
    {
        var user = ReadInt(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring");
        var policy = ReadInt(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring");
        return user != 1 && policy != 1;
    }

    private static bool FirewallOn()
    {
        const string basePath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
        foreach (var profile in new[] { "DomainProfile", "StandardProfile", "PublicProfile" })
            if (ReadInt($@"{basePath}\{profile}", "EnableFirewall") == 0) return false;
        return true;
    }

    private static bool VssNotDisabled() => ReadInt(@"SYSTEM\CurrentControlSet\Services\VSS", "Start") != 4;

    private static bool ServiceRunning(string name)
    {
        using var service = new ServiceController(name);
        return service.Status == ServiceControllerStatus.Running;
    }

    public void Dispose() => Stop();
}
