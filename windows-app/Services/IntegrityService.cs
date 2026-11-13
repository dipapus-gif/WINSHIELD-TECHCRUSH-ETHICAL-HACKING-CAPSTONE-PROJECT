using WinShield.Core;
using WinShield.Data;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>Builds the SHA-256 baseline of the protected folders and compares the current state against it.</summary>
public sealed class IntegrityService
{
    private readonly ProtectionRepository _repo;
    private readonly SettingsService _settings;
    private readonly HoneypotService _honeypots;

    public IntegrityService(ProtectionRepository repo, SettingsService settings, HoneypotService honeypots)
    {
        _repo = repo;
        _settings = settings;
        _honeypots = honeypots;
    }

    /// <summary>The most recent comparison, so reports can include it.</summary>
    public IntegrityReport? LastReport { get; private set; }

    public (int Count, DateTime? CreatedUtc) BaselineInfo => _repo.GetBaselineInfo();

    private List<string> Roots() =>
        _settings.Current.ProtectedFolders.Where(Directory.Exists).Select(Path.GetFullPath).ToList();

    /// <summary>Hashes every file in the protected folders and stores the result as the new baseline.</summary>
    public int BuildBaseline(IProgress<int>? progress = null, CancellationToken ct = default)
    {
        var snapshot = IntegrityScanner.BuildSnapshot(Roots(), _honeypots.IsHoneypot, progress, ct);
        var entries = snapshot.Files.Values
            .Select(f => new BaselineEntry(f.Path, f.Sha256, f.Size, f.LastWriteUtc))
            .ToList();
        _repo.ReplaceBaseline(entries);
        LastReport = null;
        return entries.Count;
    }

    /// <summary>Compares the folders as they are now with the stored baseline.</summary>
    public (IntegrityReport Report, List<IntegrityChange> Changes) Compare(IProgress<int>? progress = null,
        CancellationToken ct = default)
    {
        var info = _repo.GetBaselineInfo();
        if (info.Count == 0)
            throw new InvalidOperationException("There is no baseline yet. Build one first, while you know the files are clean.");

        var roots = Roots();
        var baseline = new IntegritySnapshot { CreatedUtc = info.CreatedUtc ?? DateTime.UtcNow, Roots = roots };
        foreach (var entry in _repo.GetBaseline().Values)
        {
            // Entries from folders that are no longer protected must not show up as "deleted".
            if (!roots.Any(r => AppPaths.IsUnder(entry.FilePath, r))) continue;
            baseline.Files[entry.FilePath] = new FileFingerprint(entry.FilePath, entry.Sha256, entry.Size, entry.LastWriteUtc);
        }

        var current = IntegrityScanner.BuildSnapshot(roots, _honeypots.IsHoneypot, progress, ct);
        var report = IntegrityScanner.Compare(baseline, current);
        LastReport = report;
        return (report, report.Flatten(baseline.Files, current.Files));
    }
}
