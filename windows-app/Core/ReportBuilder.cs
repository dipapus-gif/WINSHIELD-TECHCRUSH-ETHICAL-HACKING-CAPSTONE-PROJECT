using System.Net;
using System.Text;
using WinShield.Models;

namespace WinShield.Core;

/// <summary>An incident together with everything the report says about it.</summary>
public sealed class IncidentReport
{
    public Incident Incident { get; set; } = new();
    public List<IncidentAction> Actions { get; set; } = new();
    public List<string> AffectedFiles { get; set; } = new();
    public List<string> Recommendations { get; set; } = new();
}

public sealed class ReportData
{
    public DateTime GeneratedUtc { get; set; } = DateTime.UtcNow;
    public string MachineName { get; set; } = Environment.MachineName;
    public string UserName { get; set; } = Environment.UserName;
    public List<string> ProtectedFolders { get; set; } = new();
    public List<IncidentReport> Incidents { get; set; } = new();
    public IntegrityReport? Integrity { get; set; }
    public List<BackupPoint> RecoveryPoints { get; set; } = new();
    public List<QuarantineItem> Quarantine { get; set; } = new();
    public int HoneypotCount { get; set; }
    public int FileEvents24h { get; set; }
    public bool NetworkIsolated { get; set; }
    public List<string> GeneralAdvice { get; set; } = new();
}

/// <summary>Builds self-contained HTML and CSV security reports. Every dynamic value is encoded.</summary>
public static class ReportBuilder
{
    private static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    private static string Badge(Severity s) => $"<span class=\"badge {s.ToString().ToLowerInvariant()}\">{s}</span>";

    public static string BuildHtml(ReportData d)
    {
        var sb = new StringBuilder();
        var open = d.Incidents.Count(i => i.Incident.Status is "Open" or "Contained");
        var critical = d.Incidents.Count(i => i.Incident.Severity == Severity.Critical);

        sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">");
        sb.Append("<title>WinShield security report</title><style>");
        sb.Append("body{font-family:Segoe UI,Arial,sans-serif;margin:32px auto;max-width:980px;color:#1b2430;padding:0 16px}");
        sb.Append("h1{margin-bottom:4px}h2{margin-top:32px;border-bottom:1px solid #d8dde4;padding-bottom:6px}");
        sb.Append("table{border-collapse:collapse;width:100%;margin:10px 0}th,td{border:1px solid #d8dde4;padding:6px 8px;text-align:left;vertical-align:top;font-size:13px}");
        sb.Append("th{background:#f2f4f7}.muted{color:#5b6472}.badge{color:#fff;padding:1px 8px;border-radius:9px;font-size:12px}");
        sb.Append(".critical{background:#9b1c1c}.high{background:#c93c3c}.medium{background:#d98e04}.low{background:#2e7d9d}.info{background:#6b7280}");
        sb.Append(".card{border:1px solid #d8dde4;border-radius:8px;padding:12px 16px;margin:14px 0}code{font-size:12px;word-break:break-all}");
        sb.Append("</style></head><body>");

        sb.Append("<h1>WinShield security report</h1>");
        sb.Append($"<div class=\"muted\">Generated {E(d.GeneratedUtc.ToLocalTime().ToString("f"))} for {E(d.MachineName)} (user {E(d.UserName)})</div>");

        sb.Append("<h2>Summary</h2><table>");
        sb.Append($"<tr><th>Incidents in this report</th><td>{d.Incidents.Count}</td><th>Still open or contained</th><td>{open}</td></tr>");
        sb.Append($"<tr><th>Critical incidents</th><td>{critical}</td><th>Decoy files deployed</th><td>{d.HoneypotCount}</td></tr>");
        sb.Append($"<tr><th>Recovery points</th><td>{d.RecoveryPoints.Count}</td><th>File events (last 24 h)</th><td>{d.FileEvents24h}</td></tr>");
        sb.Append($"<tr><th>Network isolation</th><td colspan=\"3\">{(d.NetworkIsolated ? "ACTIVE - this computer is cut off from the network" : "Not active")}</td></tr>");
        sb.Append("</table>");

        sb.Append("<h2>Protected folders</h2>");
        if (d.ProtectedFolders.Count == 0) sb.Append("<p class=\"muted\">None configured.</p>");
        else
        {
            sb.Append("<ul>");
            foreach (var dir in d.ProtectedFolders) sb.Append($"<li><code>{E(dir)}</code></li>");
            sb.Append("</ul>");
        }

        sb.Append("<h2>Incidents</h2>");
        if (d.Incidents.Count == 0) sb.Append("<p class=\"muted\">No incidents were recorded.</p>");

        foreach (var r in d.Incidents.OrderByDescending(x => x.Incident.TimeUtc))
        {
            var i = r.Incident;
            sb.Append("<div class=\"card\">");
            sb.Append($"<strong>{E(i.Title)}</strong> {Badge(i.Severity)}");
            sb.Append($"<div class=\"muted\">Detected {E(i.TimeLocal.ToString("G"))} &middot; status: {E(i.Status)} &middot; score {i.Score:0}/100 &middot; rules: {E(i.RuleIds)}</div>");
            if (!string.IsNullOrWhiteSpace(i.Description)) sb.Append($"<p>{E(i.Description)}</p>");

            sb.Append($"<div>Responsible process: <strong>{E(i.ProcessText)}</strong> &middot; identification confidence: {E(i.Attribution)}");
            if (!string.IsNullOrEmpty(i.ProcessPath)) sb.Append($" &middot; <code>{E(i.ProcessPath)}</code>");
            sb.Append("</div>");

            if (r.AffectedFiles.Count > 0)
            {
                sb.Append($"<p><strong>Affected files</strong> ({Math.Max(i.AffectedCount, r.AffectedFiles.Count)})</p><ul>");
                foreach (var f in r.AffectedFiles.Take(25)) sb.Append($"<li><code>{E(f)}</code></li>");
                if (r.AffectedFiles.Count > 25) sb.Append($"<li class=\"muted\">... and {r.AffectedFiles.Count - 25} more</li>");
                sb.Append("</ul>");
            }

            sb.Append("<p><strong>Defensive actions taken</strong></p>");
            if (r.Actions.Count == 0) sb.Append("<p class=\"muted\">None.</p>");
            else
            {
                sb.Append("<table><tr><th>Time</th><th>Action</th><th>Detail</th><th>Result</th></tr>");
                foreach (var a in r.Actions)
                    sb.Append($"<tr><td>{E(a.TimeLocal.ToString("T"))}</td><td>{E(a.Action)}</td><td>{E(a.Detail)}</td><td>{E(a.Result)}</td></tr>");
                sb.Append("</table>");
            }

            if (!string.IsNullOrEmpty(i.EvidencePath)) sb.Append($"<div>Evidence folder: <code>{E(i.EvidencePath)}</code></div>");

            if (r.Recommendations.Count > 0)
            {
                sb.Append("<p><strong>Recommendations</strong></p><ul>");
                foreach (var rec in r.Recommendations) sb.Append($"<li>{E(rec)}</li>");
                sb.Append("</ul>");
            }
            sb.Append("</div>");
        }

        if (d.Integrity is { } integrity)
        {
            sb.Append("<h2>File integrity comparison</h2>");
            sb.Append($"<p>Compared on {E(integrity.ComparedUtc.ToLocalTime().ToString("G"))} against the baseline from {E(integrity.BaselineUtc.ToLocalTime().ToString("G"))}: ");
            sb.Append($"{integrity.Modified.Count} modified, {integrity.Deleted.Count} deleted, {integrity.Renamed.Count} renamed, {integrity.Added.Count} new, {integrity.Unchanged} unchanged.</p>");
            var rows = integrity.Flatten();
            if (rows.Count > 0)
            {
                sb.Append("<table><tr><th>Change</th><th>File</th><th>Detail</th></tr>");
                foreach (var row in rows.Take(200))
                    sb.Append($"<tr><td>{E(row.Kind)}</td><td><code>{E(row.FilePath)}</code></td><td>{E(row.Detail)}</td></tr>");
                sb.Append("</table>");
                if (rows.Count > 200) sb.Append($"<p class=\"muted\">Showing 200 of {rows.Count} changes.</p>");
            }
        }

        if (d.Quarantine.Count > 0)
        {
            sb.Append("<h2>Quarantined files</h2><table><tr><th>When</th><th>Original location</th><th>SHA-256</th><th>State</th></tr>");
            foreach (var q in d.Quarantine.Take(50))
                sb.Append($"<tr><td>{E(q.TimeLocal.ToString("G"))}</td><td><code>{E(q.OriginalPath)}</code></td><td><code>{E(q.Sha256)}</code></td><td>{E(q.StateText)}</td></tr>");
            sb.Append("</table>");
        }

        sb.Append("<h2>Recovery points</h2>");
        if (d.RecoveryPoints.Count == 0) sb.Append("<p class=\"muted\">No recovery points exist yet. Create one before you need it.</p>");
        else
        {
            sb.Append("<table><tr><th>Created</th><th>Files</th><th>Size</th><th>State</th></tr>");
            foreach (var p in d.RecoveryPoints.Take(20))
                sb.Append($"<tr><td>{E(p.CreatedLocal.ToString("G"))}</td><td>{p.FileCount}</td><td>{E(p.SizeText)}</td><td>{E(p.StateText)}</td></tr>");
            sb.Append("</table>");
        }

        sb.Append("<h2>Preventing future incidents</h2><ul>");
        foreach (var tip in d.GeneralAdvice) sb.Append($"<li>{E(tip)}</li>");
        sb.Append("</ul></body></html>");

        return sb.ToString();
    }

    private static string Csv(string? s)
    {
        s ??= "";
        // Cells starting with these characters can be run as formulas when the file is opened in a spreadsheet.
        if (s.Length > 0 && "=+-@\t\r".Contains(s[0])) s = "'" + s;
        return "\"" + s.Replace("\"", "\"\"") + "\"";
    }

    /// <summary>One row per incident, for spreadsheets.</summary>
    public static string BuildCsv(ReportData d)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Id,Detected (local),Severity,Score,Status,Title,Process,Process path,Identification confidence,Affected files,Actions taken,Evidence folder");
        foreach (var r in d.Incidents.OrderByDescending(x => x.Incident.TimeUtc))
        {
            var i = r.Incident;
            var actions = string.Join("; ", r.Actions.Select(a => $"{a.Action} ({a.Result})"));
            sb.AppendLine(string.Join(",",
                i.Id, Csv(i.TimeLocal.ToString("yyyy-MM-dd HH:mm:ss")), i.Severity, i.Score.ToString("0"), Csv(i.Status),
                Csv(i.Title), Csv(i.ProcessText), Csv(i.ProcessPath), Csv(i.Attribution),
                Math.Max(i.AffectedCount, r.AffectedFiles.Count), Csv(actions), Csv(i.EvidencePath)));
        }
        return sb.ToString();
    }
}
