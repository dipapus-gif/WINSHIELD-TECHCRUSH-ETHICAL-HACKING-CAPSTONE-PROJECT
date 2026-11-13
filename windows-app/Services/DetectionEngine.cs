using System.Text.RegularExpressions;
using WinShield.Core;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Rule-based ransomware detection over a sliding window of file activity, with an optional ML score on top.
/// Distinct files are counted (not raw events) so one busy file cannot trigger an alert on its own.
/// </summary>
public sealed class DetectionEngine : IDisposable
{
    private static readonly HashSet<string> SuspiciousExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".locked", ".lock", ".encrypted", ".encrypt", ".enc", ".crypt", ".crypted", ".crypto", ".cry",
        ".crypz", ".cerber", ".locky", ".zepto", ".wncry", ".wnry", ".wcry", ".ryk", ".conti",
        ".lockbit", ".blackcat", ".akira", ".royal", ".rhysida", ".basta"
    };

    // File names typical of ransom notes ("HOW_TO_DECRYPT.txt", "!!!README!!!.html", ...).
    private static readonly Regex NotePattern = new(
        @"(how[_\- ]?to[_\- ]?(decrypt|recover|restore))|(decrypt[_\- ]?(your[_\- ]?)?files?)|" +
        @"(recover[_\- ]?(your[_\- ]?)?files?)|(restore[_\- ]?(your[_\- ]?)?files?)|(your[_\- ]?files[_\- ]?(are|have))|" +
        @"(ransom)|(!+readme!*)|(_readme_)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly HashSet<string> NoteExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".txt", ".html", ".htm", ".hta", ".url", ".rtf", ".md" };

    private readonly Func<AppSettings> _settings;
    private readonly ThreatClassifier _classifier;
    private readonly Queue<FileActivity> _events = new();
    private readonly object _gate = new();
    private readonly Timer _timer;

    private readonly HashSet<string> _reportedRules = new();
    private readonly object _ruleGate = new();
    private Severity _lastSeverity = Severity.Info;
    private DateTime _lastEmitUtc = DateTime.MinValue;
    private volatile LiveMetrics _metrics = LiveMetrics.Empty;

    public DetectionEngine(Func<AppSettings> settings, ThreatClassifier classifier)
    {
        _settings = settings;
        _classifier = classifier;
        _timer = new Timer(_ => SafeEvaluate(false), null, 1000, 1000);
    }

    public event Action<DetectionResult>? Detected;

    public LiveMetrics Metrics => _metrics;

    public void Process(FileActivity activity)
    {
        lock (_gate) _events.Enqueue(activity);

        // A touched decoy file is an immediate alarm: do not wait for the next tick.
        if (activity.IsHoneypot && activity.Kind != FileEventKind.Created)
            SafeEvaluate(true);
    }

    /// <summary>Called when the OS dropped file notifications because activity was too heavy.</summary>
    public void ReportOverflow(string message)
    {
        Emit(new DetectionResult
        {
            Severity = Severity.Medium,
            Score = 40,
            Title = "File activity overload",
            Description = $"The file-system notification buffer overflowed ({message}). " +
                          "This happens during very heavy file activity, which can include mass encryption.",
            RuleIds = { "R-OVERFLOW" }
        });
    }

    public void Reset()
    {
        lock (_gate) _events.Clear();
        lock (_ruleGate) _reportedRules.Clear();
        _lastSeverity = Severity.Info;
        _lastEmitUtc = DateTime.MinValue;
        _metrics = LiveMetrics.Empty;
    }

    private void SafeEvaluate(bool force)
    {
        try { Evaluate(force); }
        catch { /* never let a detector crash the app */ }
    }

    private void Evaluate(bool force)
    {
        var s = _settings();
        var cutoff = DateTime.UtcNow.AddSeconds(-s.WindowSeconds);

        List<FileActivity> snapshot;
        lock (_gate)
        {
            while (_events.Count > 0 && _events.Peek().TimeUtc < cutoff) _events.Dequeue();
            snapshot = _events.ToList();
        }

        var modified = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var renamed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var extChanged = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var suspiciousExt = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deleted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var highEntropy = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var notes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var decoys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var dirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var e in snapshot)
        {
            switch (e.Kind)
            {
                case FileEventKind.Created:
                case FileEventKind.Modified:
                    modified.Add(e.FilePath);
                    dirs.Add(Path.GetDirectoryName(e.FilePath) ?? "");
                    if (e.Kind == FileEventKind.Created)
                    {
                        if (SuspiciousExtensions.Contains(e.Extension)) suspiciousExt.Add(e.FilePath);
                        if (IsRansomNote(e)) notes.Add(e.FilePath);
                    }
                    break;

                case FileEventKind.Renamed:
                    renamed.Add(e.FilePath);
                    dirs.Add(Path.GetDirectoryName(e.FilePath) ?? "");
                    if (!string.Equals(e.Extension, e.OldExtension, StringComparison.OrdinalIgnoreCase))
                        extChanged.Add(e.FilePath);
                    if (SuspiciousExtensions.Contains(e.Extension) &&
                        !SuspiciousExtensions.Contains(e.OldExtension ?? ""))
                        suspiciousExt.Add(e.FilePath);
                    break;

                case FileEventKind.Deleted:
                    deleted.Add(e.FilePath);
                    break;
            }

            if (e.Kind != FileEventKind.Deleted && e.Entropy >= s.HighEntropyThreshold &&
                !EntropyCalculator.IsExpectedHighEntropy(e.Extension))
                highEntropy.Add(e.FilePath);

            if (e.IsHoneypot && e.Kind != FileEventKind.Created)
                decoys.Add(e.FilePath);
        }

        // ---- rules ----
        double points = 0;
        var rules = new List<string>();
        var reasons = new List<string>();

        void Rule(string id, double pts, string reason)
        {
            points += pts;
            rules.Add(id);
            reasons.Add(reason);
        }

        if (modified.Count >= s.MassModifyThreshold * 2)
            Rule("R-MASS-MODIFY", 35, $"{modified.Count} files were created or modified within {s.WindowSeconds} seconds.");
        else if (modified.Count >= s.MassModifyThreshold)
            Rule("R-MASS-MODIFY", 25, $"{modified.Count} files were created or modified within {s.WindowSeconds} seconds.");

        if (extChanged.Count >= s.MassRenameThreshold)
            Rule("R-EXT-CHANGE", 30, $"{extChanged.Count} files had their extension changed.");

        if (suspiciousExt.Count >= s.SuspiciousExtThreshold)
            Rule("R-SUSPICIOUS-EXT", 35, $"{suspiciousExt.Count} files now use extensions typical of ransomware (for example .locked or .encrypted).");
        else if (suspiciousExt.Count >= 1)
            Rule("R-SUSPICIOUS-EXT", 15, $"{suspiciousExt.Count} file(s) with a ransomware-style extension appeared.");

        if (highEntropy.Count >= s.HighEntropyFileCount)
            Rule("R-ENTROPY", 30, $"{highEntropy.Count} files that are normally not compressed now contain near-random data (possible encryption).");

        if (notes.Count >= 2)
            Rule("R-RANSOM-NOTE", 35, $"{notes.Count} files named like ransom notes were created.");
        else if (notes.Count == 1)
            Rule("R-RANSOM-NOTE", 25, "A file named like a ransom note was created.");

        if (deleted.Count >= s.MassDeleteThreshold)
            Rule("R-MASS-DELETE", 20, $"{deleted.Count} files were deleted within {s.WindowSeconds} seconds.");

        if (decoys.Count > 0)
            Rule("R-HONEYPOT", 60, $"{decoys.Count} decoy file(s) were modified, renamed or deleted. Nothing legitimate should touch them.");

        var features = new Dictionary<string, double>
        {
            ["modified"] = modified.Count,
            ["renamed"] = renamed.Count,
            ["extChanged"] = extChanged.Count,
            ["suspiciousExt"] = suspiciousExt.Count,
            ["highEntropy"] = highEntropy.Count,
            ["deleted"] = deleted.Count,
            ["dirs"] = dirs.Count,
            ["notes"] = notes.Count,
            ["honeypot"] = decoys.Count
        };

        var ruleScore = Math.Min(100, points);
        var ml = _classifier.Available ? _classifier.Score(features) : 0;

        double final;
        if (rules.Count > 0)
        {
            // The model can raise a score but never lower what the rules found.
            final = _classifier.Available ? Math.Max(ruleScore, 0.5 * ruleScore + 0.5 * ml) : ruleScore;
            if (decoys.Count > 0) final = Math.Max(final, 90);
        }
        else
        {
            // No rule fired: only a very confident model result is allowed to raise an alert.
            final = ml >= 80 ? ml * 0.6 : 0;
            if (final > 0) { rules.Add("R-ML"); reasons.Add($"The classifier rated this activity {ml:0}% ransomware-like."); }
        }

        final = Math.Round(Math.Min(100, final), 1);
        _metrics = new LiveMetrics(modified.Count, renamed.Count, deleted.Count, highEntropy.Count, final);

        var severity = final >= 85 ? Severity.Critical
                     : final >= 60 ? Severity.High
                     : final >= 35 ? Severity.Medium
                     : Severity.Info;

        var now = DateTime.UtcNow;
        if (severity < Severity.Medium)
        {
            if (now - _lastEmitUtc > TimeSpan.FromSeconds(60))
            {
                _lastSeverity = Severity.Info;
                lock (_ruleGate) _reportedRules.Clear();
            }
            return;
        }

        // Alert on escalation, every 30 s while activity continues, and whenever a rule fires that the
        // current alert has not reported yet (for example a decoy touched or a ransom note dropped
        // after the first alert). Each rule id can only be new once per episode, so this cannot flood.
        var escalated = severity > _lastSeverity;
        var repeat = now - _lastEmitUtc > TimeSpan.FromSeconds(30);
        bool newRule;
        lock (_ruleGate) newRule = rules.Any(r => !_reportedRules.Contains(r));
        if (!force && !escalated && !repeat && !newRule) return;
        if (force && !escalated && !newRule && now - _lastEmitUtc < TimeSpan.FromSeconds(5)) return;

        var affected = modified.Concat(renamed).Concat(deleted).Concat(suspiciousExt).Concat(decoys)
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(500).ToList();

        var title = decoys.Count > 0 ? "Decoy file triggered"
                  : severity >= Severity.High ? "Possible ransomware activity"
                  : "Suspicious file activity";

        Emit(new DetectionResult
        {
            Severity = severity,
            Score = final,
            Title = title,
            Description = string.Join(" ", reasons),
            RuleIds = rules,
            AffectedFiles = affected,
            Features = features,
            SuggestsProcessAction = severity >= Severity.High
        });
    }

    private void Emit(DetectionResult result)
    {
        _lastSeverity = result.Severity;
        _lastEmitUtc = DateTime.UtcNow;
        lock (_ruleGate)
            foreach (var r in result.RuleIds) _reportedRules.Add(r);
        Detected?.Invoke(result);
    }

    private static bool IsRansomNote(FileActivity e)
    {
        if (!NoteExtensions.Contains(e.Extension)) return false;
        return NotePattern.IsMatch(Path.GetFileNameWithoutExtension(e.FilePath));
    }

    public void Dispose() => _timer.Dispose();
}
