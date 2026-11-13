using System.Security.Cryptography;
using WinShield.Models;

namespace WinShield.Core;

public sealed record FileFingerprint(string Path, string Sha256, long Size, DateTime LastWriteUtc);

public sealed class IntegritySnapshot
{
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public List<string> Roots { get; set; } = new();
    public Dictionary<string, FileFingerprint> Files { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public List<string> Unreadable { get; set; } = new();
}

public sealed class IntegrityReport
{
    public DateTime ComparedUtc { get; set; } = DateTime.UtcNow;
    public DateTime BaselineUtc { get; set; }
    public List<string> Added { get; } = new();
    public List<string> Modified { get; } = new();
    public List<string> Deleted { get; } = new();
    public List<(string Old, string New)> Renamed { get; } = new();
    public int Unchanged { get; set; }
    public int Unreadable { get; set; }

    public bool HasChanges => TotalChanges > 0;
    public int TotalChanges => Added.Count + Modified.Count + Deleted.Count + Renamed.Count;

    /// <summary>One row per change, most serious first, ready for a grid or a report.</summary>
    public List<IntegrityChange> Flatten(IReadOnlyDictionary<string, FileFingerprint>? baseline = null,
        IReadOnlyDictionary<string, FileFingerprint>? current = null)
    {
        string? Old(string p) => baseline is not null && baseline.TryGetValue(p, out var f) ? f.Sha256 : null;
        string? New(string p) => current is not null && current.TryGetValue(p, out var f) ? f.Sha256 : null;

        var rows = new List<IntegrityChange>();
        rows.AddRange(Modified.Select(p => new IntegrityChange { Kind = "Modified", FilePath = p, OldSha256 = Old(p), NewSha256 = New(p) }));
        rows.AddRange(Deleted.Select(p => new IntegrityChange { Kind = "Deleted", FilePath = p, OldSha256 = Old(p) }));
        rows.AddRange(Renamed.Select(r => new IntegrityChange { Kind = "Renamed", FilePath = r.New, PreviousPath = r.Old, OldSha256 = Old(r.Old), NewSha256 = New(r.New) }));
        rows.AddRange(Added.Select(p => new IntegrityChange { Kind = "New", FilePath = p, NewSha256 = New(p) }));
        return rows;
    }
}

/// <summary>SHA-256 baselines of protected folders and comparison against them. Pure file logic, no database.</summary>
public static class IntegrityScanner
{
    private static readonly EnumerationOptions EnumOptions = new()
    {
        RecurseSubdirectories = true,
        IgnoreInaccessible = true,
        // Skip junctions and symlinks (loops) and cloud placeholders (reading them would trigger a download).
        AttributesToSkip = FileAttributes.ReparsePoint | FileAttributes.Offline
    };

    public static IEnumerable<string> EnumerateFiles(string root) =>
        Directory.EnumerateFiles(root, "*", EnumOptions);

    public static string HashFile(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete, 81920, FileOptions.SequentialScan);
        return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
    }

    public static IntegritySnapshot BuildSnapshot(IEnumerable<string> roots, Func<string, bool>? exclude = null,
        IProgress<int>? progress = null, CancellationToken ct = default)
    {
        var snapshot = new IntegritySnapshot();
        var count = 0;

        foreach (var rawRoot in roots)
        {
            var root = Path.GetFullPath(rawRoot);
            if (!Directory.Exists(root)) continue;
            snapshot.Roots.Add(root);

            foreach (var file in EnumerateFiles(root))
            {
                ct.ThrowIfCancellationRequested();
                if (AppPaths.IsInternal(file) || (exclude?.Invoke(file) ?? false)) continue;

                try
                {
                    var info = new FileInfo(file);
                    snapshot.Files[file] = new FileFingerprint(file, HashFile(file), info.Length, info.LastWriteTimeUtc);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    snapshot.Unreadable.Add(file);
                }

                if (++count % 200 == 0) progress?.Report(count);
            }
        }

        progress?.Report(count);
        return snapshot;
    }

    public static IntegrityReport Compare(IntegritySnapshot baseline, IntegritySnapshot current)
    {
        var report = new IntegrityReport { BaselineUtc = baseline.CreatedUtc, Unreadable = current.Unreadable.Count };

        var unreadable = new HashSet<string>(current.Unreadable, StringComparer.OrdinalIgnoreCase);
        var deleted = new List<FileFingerprint>();
        foreach (var (path, old) in baseline.Files)
        {
            if (!current.Files.TryGetValue(path, out var now))
            {
                // A file that could not be read this time (locked, for example) is not evidence of deletion.
                if (!unreadable.Contains(path)) deleted.Add(old);
            }
            else if (!string.Equals(old.Sha256, now.Sha256, StringComparison.Ordinal)) report.Modified.Add(path);
            else report.Unchanged++;
        }

        var added = current.Files.Values.Where(f => !baseline.Files.ContainsKey(f.Path)).ToList();

        // A file that vanished while an identical file (same hash) appeared elsewhere was renamed or moved.
        var addedByHash = added.Where(f => f.Size > 0).GroupBy(f => f.Sha256)
            .ToDictionary(g => g.Key, g => new Queue<FileFingerprint>(g));
        var renamedTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var gone in deleted)
        {
            if (gone.Size > 0 && addedByHash.TryGetValue(gone.Sha256, out var queue) && queue.Count > 0)
            {
                var target = queue.Dequeue();
                report.Renamed.Add((gone.Path, target.Path));
                renamedTargets.Add(target.Path);
            }
            else
            {
                report.Deleted.Add(gone.Path);
            }
        }

        report.Added.AddRange(added.Where(f => !renamedTargets.Contains(f.Path)).Select(f => f.Path));
        report.Modified.Sort(StringComparer.OrdinalIgnoreCase);
        report.Deleted.Sort(StringComparer.OrdinalIgnoreCase);
        report.Added.Sort(StringComparer.OrdinalIgnoreCase);
        return report;
    }
}
