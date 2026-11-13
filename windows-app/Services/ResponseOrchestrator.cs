using System.Diagnostics;
using WinShield.Core;
using WinShield.Data;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Turns detections into incidents and decides what to do about them. Reversible actions (suspend, isolate)
/// are preferred; disruptive ones (terminate, isolate the network) always need the user's consent unless the
/// user explicitly enabled automatic containment. Protected and trusted processes are never touched.
/// </summary>
public sealed class ResponseOrchestrator
{
    private readonly SettingsService _settings;
    private readonly ProtectionRepository _repo;
    private readonly ProcessController _processes;
    private readonly QuarantineService _quarantine;
    private readonly NetworkIsolationService _network;
    private readonly EvidenceService _evidence;
    private readonly ControlledFolderAccessService _cfa;
    private readonly ProcessBehaviorMonitor _behavior;
    private readonly Func<IReadOnlyList<FileActivity>> _recentActivity;

    private readonly SemaphoreSlim _incidentGate = new(1, 1);
    private readonly SemaphoreSlim _promptGate = new(1, 1);
    private readonly Dictionary<string, DateTime> _declined = new();

    private Incident? _active;
    private DateTime _activeUtc;
    private Incident? _lastIncident;

    public ResponseOrchestrator(
        SettingsService settings, ProtectionRepository repo, ProcessController processes,
        QuarantineService quarantine, NetworkIsolationService network, EvidenceService evidence,
        ControlledFolderAccessService cfa, ProcessBehaviorMonitor behavior,
        Func<IReadOnlyList<FileActivity>> recentActivity)
    {
        _settings = settings;
        _repo = repo;
        _processes = processes;
        _quarantine = quarantine;
        _network = network;
        _evidence = evidence;
        _cfa = cfa;
        _behavior = behavior;
        _recentActivity = recentActivity;
    }

    /// <summary>Set by the UI: shows a question to the user and returns their answer (title, message).</summary>
    public Func<string, string, Task<bool>>? ConfirmAsync { get; set; }

    public event Action<Incident>? IncidentChanged;
    public event Action<IncidentAction>? ActionRecorded;
    public event Action? EmergencyChanged;

    public bool EmergencyActive { get; private set; }

    private AppSettings Settings => _settings.Current;

    // ------------------------------------------------------------------
    // Entry point for every detector
    // ------------------------------------------------------------------

    public async Task HandleAsync(DetectionResult detection)
    {
        Incident incident;
        await _incidentGate.WaitAsync();
        try
        {
            AttributeProcess(detection);
            (incident, _) = UpsertIncident(detection);
            if (detection.Severity >= Severity.High && incident.EvidencePath is null)
                CaptureEvidence(incident, detection);
        }
        finally
        {
            _incidentGate.Release();
        }

        IncidentChanged?.Invoke(incident);
        await RespondAsync(incident, detection);
    }

    private (Incident Incident, bool Created) UpsertIncident(DetectionResult d)
    {
        var now = DateTime.UtcNow;
        var ruleText = string.Join(",", d.RuleIds);

        // Detections that arrive within two minutes belong to the same ongoing event.
        if (_active is not null && _active.Status is "Open" or "Contained" && (now - _activeUtc).TotalSeconds <= 120)
        {
            var inc = _active;
            if (d.Severity > inc.Severity)
            {
                inc.Severity = d.Severity;
                inc.Title = d.Title;
            }
            inc.Score = Math.Max(inc.Score, d.Score);

            var known = inc.RuleIds.Split(',', StringSplitOptions.RemoveEmptyEntries).ToList();
            foreach (var r in d.RuleIds.Where(r => !known.Contains(r))) known.Add(r);
            inc.RuleIds = string.Join(",", known);

            if (inc.ProcessId is null && d.ProcessId is not null)
            {
                inc.ProcessId = d.ProcessId;
                inc.ProcessName = d.ProcessName;
                inc.ProcessPath = d.ProcessPath;
                inc.Attribution = d.Attribution;
            }

            if (!inc.Description.Contains(d.Description, StringComparison.Ordinal))
            {
                var combined = inc.Description + " | " + d.Description;
                inc.Description = combined.Length > 3000 ? combined[..3000] : combined;
            }

            _repo.AddIncidentFiles(inc.Id, d.AffectedFiles, ruleText);
            inc.AffectedCount = _repo.CountIncidentFiles(inc.Id);
            _repo.UpdateIncident(inc);
            _activeUtc = now;
            _lastIncident = inc;
            return (inc, false);
        }

        var id = _repo.AddIncident(d);
        _repo.AddIncidentFiles(id, d.AffectedFiles, ruleText);
        var created = _repo.GetIncident(id)!;
        _active = created;
        _activeUtc = now;
        _lastIncident = created;
        return (created, true);
    }

    private void CaptureEvidence(Incident incident, DetectionResult detection)
    {
        try
        {
            var path = _evidence.Capture(incident, detection, _recentActivity());
            incident.EvidencePath = path;
            _repo.SetIncidentEvidence(incident.Id, path);
            Record(incident, "Evidence preserved", path, true);
        }
        catch (Exception ex)
        {
            Record(incident, "Evidence preserved", $"Could not capture evidence: {ex.Message}", false);
        }
    }

    // ------------------------------------------------------------------
    // Who did it?
    // ------------------------------------------------------------------

    private void AttributeProcess(DetectionResult d)
    {
        if (d.ProcessId is not null) return;
        if (!d.RuleIds.Any(r => r.StartsWith("R-", StringComparison.Ordinal))) return;

        var trusted = Settings.TrustedProcesses;

        // 1. Which program has one of the affected files open right now? (best evidence)
        foreach (var file in d.AffectedFiles.Take(3))
        {
            foreach (var pid in Win32.GetLockingProcessIds(file))
            {
                var name = SafeName(pid);
                var path = Win32.TryGetProcessPath(pid);
                if (name is null || ProcessSafety.WhyProtected(pid, name, path, trusted) is not null) continue;

                d.ProcessId = pid;
                d.ProcessName = name;
                d.ProcessPath = path;
                d.Attribution = "High";
                return;
            }
        }

        // 2. Otherwise, the heaviest recent disk writer.
        var top = _behavior.TopWriter(TimeSpan.FromSeconds(15), 5);
        if (top is not null)
        {
            d.ProcessId = top.Pid;
            d.ProcessName = top.Name;
            d.ProcessPath = top.Path;
            d.Attribution = top.Attribution;
        }
    }

    private static string? SafeName(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            return p.ProcessName;
        }
        catch
        {
            return null;
        }
    }

    // ------------------------------------------------------------------
    // What do we do about it?
    // ------------------------------------------------------------------

    private async Task RespondAsync(Incident incident, DetectionResult d)
    {
        var s = Settings;

        if (s.ResponseMode == ResponseMode.MonitorOnly)
        {
            Record(incident, "Alert", "Monitor-only mode: no automatic response was taken.", true);
            return;
        }

        if (d.Severity < Severity.High)
        {
            Record(incident, "Alert", "Logged for review. Severity is below the automatic response threshold.", true);
            return;
        }

        var candidate = GetCandidate(incident, d);
        var auto = s.ResponseMode == ResponseMode.AutoContain;

        if (d.Severity == Severity.Critical)
        {
            var go = auto || await AskAsync("emergency", "Critical ransomware threat",
                BuildPrompt(incident, candidate,
                    "Activate emergency protection? WinShield will suspend the suspect process(es), turn on " +
                    "Controlled Folder Access, and then ask before isolating the network."));

            if (go)
            {
                await ActivateEmergencyAsync(incident, candidate);
                return;
            }
            Record(incident, "Emergency protection declined", "You chose not to activate emergency protection.", true);
        }

        if (candidate is null)
        {
            Record(incident, "Alert", "No process could be identified with enough confidence to act on automatically.", true);
            return;
        }

        var suspend = auto || await AskAsync($"suspend:{candidate.Pid}", "Suspend suspicious process?",
            BuildPrompt(incident, candidate, $"Suspend {candidate.Name} (PID {candidate.Pid})? Suspending is reversible."));

        if (suspend) SuspendCandidate(incident, candidate);
        else Record(incident, "Suspend declined", $"You chose not to suspend {candidate.Name}.", true);
    }

    private ProcessRef? GetCandidate(Incident incident, DetectionResult d)
    {
        if (!d.SuggestsProcessAction || incident.ProcessId is null || incident.ProcessName is null) return null;

        var why = ProcessSafety.WhyProtected(incident.ProcessId.Value, incident.ProcessName,
            incident.ProcessPath, Settings.TrustedProcesses);
        if (why is not null)
        {
            Record(incident, "Process not acted on", $"{incident.ProcessText}: {why}.", true);
            return null;
        }

        return new ProcessRef(incident.ProcessId.Value, incident.ProcessName, incident.ProcessPath, incident.Attribution);
    }

    private static string BuildPrompt(Incident incident, ProcessRef? candidate, string question)
    {
        var who = candidate is null
            ? "No single process could be identified."
            : $"Suspected process: {candidate.Name} (PID {candidate.Pid}), confidence {candidate.Attribution}.\n{candidate.Path}";

        return $"{incident.Title} - severity {incident.Severity}, score {incident.Score:0}.\n\n" +
               $"{Shorten(incident.Description, 500)}\n\n{who}\n\n{question}";
    }

    private static string Shorten(string text, int max) => text.Length <= max ? text : text[..max] + "...";

    private void SuspendCandidate(Incident incident, ProcessRef p)
    {
        var (ok, message) = _processes.Suspend(p.Pid, p.Name, p.Path);
        Record(incident, ok ? "Process suspended" : "Suspend failed", message, ok);
        if (ok) SetStatus(incident, "Contained");
    }

    private async Task<bool> AskAsync(string key, string title, string message)
    {
        if (RecentlyDeclined(key)) return false;

        var confirm = ConfirmAsync;
        if (confirm is null) return false;

        await _promptGate.WaitAsync();
        try
        {
            if (RecentlyDeclined(key)) return false;
            var yes = await confirm(title, message);
            if (!yes) _declined[key] = DateTime.UtcNow;
            return yes;
        }
        finally
        {
            _promptGate.Release();
        }
    }

    private bool RecentlyDeclined(string key)
    {
        lock (_declined)
            return _declined.TryGetValue(key, out var at) && DateTime.UtcNow - at < TimeSpan.FromMinutes(5);
    }

    // ------------------------------------------------------------------
    // Emergency protection
    // ------------------------------------------------------------------

    private async Task ActivateEmergencyAsync(Incident incident, ProcessRef? candidate)
    {
        var s = Settings;
        Record(incident, "Emergency protection", "Emergency protection activated.", true);
        EmergencyActive = true;
        EmergencyChanged?.Invoke();

        if (candidate is not null) SuspendCandidate(incident, candidate);

        foreach (var sp in _behavior.Current.Where(x => x.Score >= 70 && !x.IsSuspended))
        {
            if (candidate is not null && sp.Pid == candidate.Pid) continue;
            if (ProcessSafety.WhyProtected(sp.Pid, sp.Name, sp.Path, s.TrustedProcesses) is not null) continue;

            var (ok, message) = _processes.Suspend(sp.Pid, sp.Name, sp.Path);
            Record(incident, ok ? "Process suspended" : "Suspend failed", $"{message} Reason: {sp.Reasons}.", ok);
        }

        if (AdminHelper.IsAdministrator)
        {
            var (ok, message) = await Task.Run(() => _cfa.Enable(s.ProtectedFolders));
            Record(incident, ok ? "Controlled Folder Access enabled" : "Controlled Folder Access", message, ok);
        }
        else
        {
            Record(incident, "Controlled Folder Access", "Skipped: administrator rights are required.", false);
        }

        var isolate = s.AutoIsolateOnCritical || await AskAsync("isolate", "Isolate this PC from the network?",
            "Blocking all network traffic stops ransomware from spreading or contacting its operators, " +
            "but you will lose internet and file-share access (including remote sessions) until you restore it.\n\n" +
            "Isolate this PC now?");

        if (isolate) IsolateNetwork(incident);
        else Record(incident, "Network isolation declined", "The network was left connected.", true);
    }

    /// <summary>Starts emergency protection on the user's request (the UI has already asked for confirmation).</summary>
    public async Task ActivateEmergencyManualAsync()
    {
        var d = new DetectionResult
        {
            Severity = Severity.High,
            Score = 100,
            Title = "Emergency protection activated manually",
            Description = "The user activated emergency protection from the dashboard.",
            RuleIds = { "M-MANUAL" }
        };

        Incident incident;
        await _incidentGate.WaitAsync();
        try { (incident, _) = UpsertIncident(d); }
        finally { _incidentGate.Release(); }

        IncidentChanged?.Invoke(incident);
        await ActivateEmergencyAsync(incident, null);
    }

    public Task ReleaseEmergencyAsync() => Task.Run(() =>
    {
        var resumed = _processes.ResumeAll();
        var networkOk = true;
        var networkMessage = "";
        if (_network.IsIsolated())
        {
            var (ok, message) = _network.Restore();
            networkOk = ok;
            networkMessage = " " + message;
        }

        EmergencyActive = false;
        EmergencyChanged?.Invoke();

        if (_lastIncident is not null)
            Record(_lastIncident, "Emergency protection released",
                $"Resumed {resumed} process(es).{networkMessage}", networkOk);
    });

    // ------------------------------------------------------------------
    // Actions the user can trigger from an incident
    // ------------------------------------------------------------------

    public (bool Ok, string Message) SuspendIncidentProcess(Incident incident)
    {
        var check = RequireProcess(incident);
        if (check is not null) return (false, check);

        var (ok, message) = _processes.Suspend(incident.ProcessId!.Value, incident.ProcessName!, incident.ProcessPath);
        Record(incident, ok ? "Process suspended" : "Suspend failed", message, ok);
        if (ok) SetStatus(incident, "Contained");
        return (ok, message);
    }

    public (bool Ok, string Message) ResumeIncidentProcess(Incident incident)
    {
        if (incident.ProcessId is null) return (false, "This incident has no identified process.");
        var (ok, message) = _processes.Resume(incident.ProcessId.Value);
        Record(incident, ok ? "Process resumed" : "Resume failed", message, ok);
        return (ok, message);
    }

    public (bool Ok, string Message) KillIncidentProcess(Incident incident)
    {
        var check = RequireProcess(incident);
        if (check is not null) return (false, check);

        var (ok, message) = _processes.Kill(incident.ProcessId!.Value, incident.ProcessName!, incident.ProcessPath);
        Record(incident, ok ? "Process terminated" : "Terminate failed", message, ok);
        if (ok) SetStatus(incident, "Contained");
        return (ok, message);
    }

    public (bool Ok, string Message) QuarantineIncidentImage(Incident incident)
    {
        if (string.IsNullOrEmpty(incident.ProcessPath))
            return (false, "The program file for this incident is unknown.");

        if (incident.ProcessName is not null && incident.ProcessId is not null)
        {
            var why = ProcessSafety.WhyProtected(incident.ProcessId.Value, incident.ProcessName,
                incident.ProcessPath, Settings.TrustedProcesses);
            if (why is not null) return (false, $"Not quarantined: {why}.");
        }

        var (ok, message, _) = _quarantine.Quarantine(incident.ProcessPath, incident.Id, incident.Title);
        Record(incident, ok ? "Image quarantined" : "Quarantine failed", message, ok);
        return (ok, message);
    }

    public (bool Ok, string Message) IsolateNetwork(Incident? incident)
    {
        var (ok, message) = _network.Isolate();
        if (incident is not null || _lastIncident is not null)
            Record(incident ?? _lastIncident!, ok ? "Network isolated" : "Network isolation failed", message, ok);
        return (ok, message);
    }

    public (bool Ok, string Message) RestoreNetwork(Incident? incident)
    {
        var (ok, message) = _network.Restore();
        if (incident is not null || _lastIncident is not null)
            Record(incident ?? _lastIncident!, ok ? "Network restored" : "Network restore failed", message, ok);
        return (ok, message);
    }

    public void SetStatus(Incident incident, string status)
    {
        incident.Status = status;
        incident.ResolvedUtc = status is "Resolved" or "FalsePositive" ? DateTime.UtcNow : null;
        _repo.SetIncidentStatus(incident.Id, status);

        if (status is "Resolved" or "FalsePositive" && _active?.Id == incident.Id) _active = null;
        IncidentChanged?.Invoke(incident);
    }

    public void TrustIncidentProcess(Incident incident)
    {
        if (incident.ProcessName is null) return;
        var name = ProcessSafety.NormalizeName(incident.ProcessName);
        if (!Settings.TrustedProcesses.Contains(name))
        {
            Settings.TrustedProcesses.Add(name);
            _settings.Save();
        }
        Record(incident, "Process trusted", $"{incident.ProcessName} was added to the trusted list.", true);
    }

    private string? RequireProcess(Incident incident)
    {
        if (incident.ProcessId is null || incident.ProcessName is null)
            return "This incident has no identified process.";

        var why = ProcessSafety.WhyProtected(incident.ProcessId.Value, incident.ProcessName,
            incident.ProcessPath, Settings.TrustedProcesses);
        return why is null ? null : $"Not allowed: {why}.";
    }

    private void Record(Incident incident, string action, string detail, bool success)
    {
        var entry = new IncidentAction
        {
            IncidentId = incident.Id,
            TimeUtc = DateTime.UtcNow,
            Action = action,
            Detail = detail,
            Success = success
        };

        try { _repo.AddAction(entry); }
        catch { /* logging must not break the response */ }

        ActionRecorded?.Invoke(entry);
    }
}
