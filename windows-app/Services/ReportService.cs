using System.Text;
using WinShield.Core;
using WinShield.Data;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>Collects incidents, actions, integrity results and recovery points into a downloadable report.</summary>
public sealed class ReportService
{
    private readonly SettingsService _settings;
    private readonly ProtectionRepository _repo;
    private readonly HoneypotService _honeypots;
    private readonly RecoveryService _recovery;
    private readonly IntegrityService _integrity;
    private readonly NetworkIsolationService _network;

    public ReportService(SettingsService settings, ProtectionRepository repo, HoneypotService honeypots,
        RecoveryService recovery, IntegrityService integrity, NetworkIsolationService network)
    {
        _settings = settings;
        _repo = repo;
        _honeypots = honeypots;
        _recovery = recovery;
        _integrity = integrity;
        _network = network;
    }

    public ReportData Collect(int incidentLimit = 200)
    {
        var isolated = false;
        try { isolated = _network.IsIsolated(); } catch { /* reporting must not fail because of this */ }

        var data = new ReportData
        {
            ProtectedFolders = _settings.Current.ProtectedFolders.ToList(),
            Integrity = _integrity.LastReport,
            HoneypotCount = _honeypots.Count,
            FileEvents24h = _repo.GetStats().FileEvents24h,
            NetworkIsolated = isolated,
            GeneralAdvice = RecommendationEngine.General(),
            Quarantine = _repo.GetQuarantine()
        };

        try { data.RecoveryPoints = _recovery.List().ToList(); }
        catch (Exception) { /* backup folder may be unavailable */ }

        foreach (var incident in _repo.GetIncidents(incidentLimit))
        {
            var actions = _repo.GetActions(incident.Id);
            data.Incidents.Add(new IncidentReport
            {
                Incident = incident,
                Actions = actions,
                AffectedFiles = _repo.GetIncidentFiles(incident.Id, 200),
                Recommendations = RecommendationEngine.ForIncident(incident, actions, isolated)
            });
        }
        return data;
    }

    /// <summary>Writes the report to <paramref name="path"/>. A .csv extension gives a spreadsheet, anything else HTML.</summary>
    public string Save(ReportData data, string path)
    {
        var full = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var csv = string.Equals(Path.GetExtension(full), ".csv", StringComparison.OrdinalIgnoreCase);
        File.WriteAllText(full, csv ? ReportBuilder.BuildCsv(data) : ReportBuilder.BuildHtml(data), new UTF8Encoding(true));
        return full;
    }

    public static string DefaultFileName(string extension) =>
        $"WinShield-report-{DateTime.Now:yyyyMMdd-HHmm}.{extension}";
}
