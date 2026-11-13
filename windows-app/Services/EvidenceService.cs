using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using WinShield.Core;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Preserves a snapshot of the machine state when a serious incident starts: recent file activity, running
/// processes, network connections, a copy of the suspect program (renamed so it cannot run) and a hash manifest.
/// </summary>
public sealed class EvidenceService
{
    private const long MaxImageCopyBytes = 50L * 1024 * 1024;

    public string Capture(Incident incident, DetectionResult? detection, IReadOnlyList<FileActivity> recentEvents)
    {
        var folder = Path.Combine(AppPaths.Evidence, $"incident_{incident.Id}_{DateTime.UtcNow:yyyyMMdd_HHmmss}");
        Directory.CreateDirectory(folder);

        WriteSummary(folder, incident, detection);
        WriteFileEvents(folder, recentEvents);
        WriteProcesses(folder);

        try
        {
            var (_, output) = ProcessRunner.Run("netstat", "-ano", 10000);
            File.WriteAllText(Path.Combine(folder, "network_connections.txt"), output);
        }
        catch
        {
            // netstat unavailable
        }

        CopySuspectImage(folder, incident);
        WriteManifest(folder);
        return folder;
    }

    private static void WriteSummary(string folder, Incident incident, DetectionResult? detection)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"WinShield evidence snapshot");
        sb.AppendLine($"Captured (UTC): {DateTime.UtcNow:o}");
        sb.AppendLine($"Machine: {Environment.MachineName}   User: {Environment.UserName}");
        sb.AppendLine($"Incident: #{incident.Id}  {incident.Severity}  {incident.Title}");
        sb.AppendLine($"Score: {incident.Score}");
        sb.AppendLine($"Rules: {incident.RuleIds}");
        sb.AppendLine($"Process: {incident.ProcessText}  ({incident.Attribution} confidence)");
        sb.AppendLine($"Process path: {incident.ProcessPath}");
        sb.AppendLine();
        sb.AppendLine("Description:");
        sb.AppendLine(incident.Description);

        if (detection is not null && detection.Features.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Detection features (counts in the detection window):");
            foreach (var (name, value) in detection.Features) sb.AppendLine($"  {name} = {value}");
        }
        File.WriteAllText(Path.Combine(folder, "summary.txt"), sb.ToString());
    }

    private static string Csv(string? value) => "\"" + (value ?? "").Replace("\"", "\"\"") + "\"";

    private static void WriteFileEvents(string folder, IReadOnlyList<FileActivity> events)
    {
        var sb = new StringBuilder("time_utc,kind,path,old_path,size,entropy,decoy\n");
        foreach (var e in events.TakeLast(2000))
            sb.AppendLine(string.Join(",", Csv(e.TimeUtc.ToString("o")), Csv(e.Kind.ToString()), Csv(e.FilePath),
                Csv(e.OldPath), e.Size, e.Entropy.ToString("0.00"), e.IsHoneypot ? 1 : 0));
        File.WriteAllText(Path.Combine(folder, "file_events.csv"), sb.ToString());
    }

    private static void WriteProcesses(string folder)
    {
        var sb = new StringBuilder("pid,name,path,start_time\n");
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                string start;
                try { start = p.StartTime.ToUniversalTime().ToString("o"); } catch { start = ""; }
                sb.AppendLine(string.Join(",", p.Id, Csv(p.ProcessName), Csv(Win32.TryGetProcessPath(p.Id)), Csv(start)));
            }
            catch
            {
                // process exited
            }
            finally
            {
                p.Dispose();
            }
        }
        File.WriteAllText(Path.Combine(folder, "processes.csv"), sb.ToString());
    }

    private static void CopySuspectImage(string folder, Incident incident)
    {
        try
        {
            var path = incident.ProcessPath;
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
            if (new FileInfo(path).Length > MaxImageCopyBytes) return;

            // .bin so the copy can never be launched by double-clicking it.
            File.Copy(path, Path.Combine(folder, "suspect_image.bin"), overwrite: true);
            File.WriteAllText(Path.Combine(folder, "suspect_image_origin.txt"),
                $"Copied from: {path}{Environment.NewLine}SHA-256: {QuarantineService.HashFile(path)}{Environment.NewLine}");
        }
        catch
        {
            // the image may be locked or unreadable: evidence is best effort
        }
    }

    private static void WriteManifest(string folder)
    {
        var sb = new StringBuilder();
        foreach (var file in Directory.EnumerateFiles(folder).OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            if (file.EndsWith("manifest.sha256", StringComparison.OrdinalIgnoreCase)) continue;
            using var stream = File.OpenRead(file);
            sb.AppendLine($"{Convert.ToHexString(SHA256.HashData(stream))}  {Path.GetFileName(file)}");
        }
        File.WriteAllText(Path.Combine(folder, "manifest.sha256"), sb.ToString());
    }
}
