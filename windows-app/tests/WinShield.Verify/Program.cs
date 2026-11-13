using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WinShield.Core;
using WinShield.Models;
using WinShield.Services;

var failures = 0;
var total = 0;

void Check(string name, bool ok, string? detail = null)
{
    total++;
    if (!ok) failures++;
    Console.WriteLine($"{(ok ? "PASS" : "FAIL")}  {name}{(!ok && detail is not null ? "  -> " + detail : "")}");
}

var tmp = Path.Combine(Path.GetTempPath(), "wsverify_" + Guid.NewGuid().ToString("N")[..8]);
Directory.CreateDirectory(tmp);
AppPaths.OverrideRoot(Path.Combine(tmp, "appdata"));
AppPaths.EnsureAll();

FileActivity Act(FileEventKind kind, string path, double entropy = 3.0, string? old = null, bool honey = false) =>
    new(DateTime.UtcNow, kind, path, old, 5000, entropy, honey);

/// <summary>Feeds events to a fresh engine and waits for the next detection (or gives up).</summary>
DetectionResult? Run(IEnumerable<FileActivity> events, int waitMs, ThreatClassifier? classifier,
    out LiveMetrics metrics)
{
    DetectionResult? found = null;
    using var gate = new ManualResetEventSlim();
    using var engine = new DetectionEngine(() => new AppSettings(), classifier ?? new ThreatClassifier());
    engine.Detected += d => { found ??= d; gate.Set(); };
    foreach (var e in events) engine.Process(e);
    gate.Wait(waitMs);
    // Metrics refresh on the engine's own 1 s tick; give it a moment so the quiet cases are measured too.
    if (found is null) Thread.Sleep(1200);
    metrics = engine.Metrics;
    return found;
}

IEnumerable<FileActivity> Many(FileEventKind kind, int count, string folder = @"C:\Docs", string ext = ".docx",
    double entropy = 3.0) =>
    Enumerable.Range(0, count).Select(i => Act(kind, $@"{folder}\f{i}{ext}", entropy));

try
{
    // ------------------------------------------------------------------ entropy
    Console.WriteLine("\n== Entropy ==");
    var random = RandomNumberGenerator.GetBytes(8192);
    Check("random bytes have entropy above 7.9", EntropyCalculator.Shannon(random) > 7.9);
    var plain = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("hello world ", 500)));
    Check("repetitive text has entropy below 4", EntropyCalculator.Shannon(plain) < 4);
    Check("empty input has zero entropy", EntropyCalculator.Shannon(ReadOnlySpan<byte>.Empty) == 0);
    var randFile = Path.Combine(tmp, "random.bin");
    File.WriteAllBytes(randFile, random);
    Check("SampleFile reads a random file as high entropy", EntropyCalculator.SampleFile(randFile) > 7.9);
    var tiny = Path.Combine(tmp, "tiny.bin");
    File.WriteAllBytes(tiny, RandomNumberGenerator.GetBytes(200));
    Check("files under 1 KB are not scored (-1)", EntropyCalculator.SampleFile(tiny) == -1);
    Check("missing file is not scored (-1)", EntropyCalculator.SampleFile(Path.Combine(tmp, "nope.bin")) == -1);
    Check("compressed types are expected to be high entropy, text is not",
        EntropyCalculator.IsExpectedHighEntropy(".zip") && EntropyCalculator.IsExpectedHighEntropy(".docx")
        && !EntropyCalculator.IsExpectedHighEntropy(".txt"));

    // ------------------------------------------------------------------ detection engine
    Console.WriteLine("\n== Detection engine (rules) ==");

    var quiet = Run(Many(FileEventKind.Modified, 10), 1500, null, out var quietMetrics);
    Check("10 modified files do not raise an alert", quiet is null);
    Check("live metrics still count the 10 files", quietMetrics.Modified == 10, $"Modified={quietMetrics.Modified}");

    var oneFile = Run(Enumerable.Range(0, 500).Select(_ => Act(FileEventKind.Modified, @"C:\Docs\busy.log")), 1500, null, out _);
    Check("one busy file written 500 times does not alarm (distinct files are counted)", oneFile is null);

    var mass = Run(Many(FileEventKind.Modified, 100), 3500, null, out _);
    Check("100 distinct files modified in the window raises an alert", mass is not null);
    Check("  ...with rule R-MASS-MODIFY and at least Medium severity",
        mass is not null && mass.RuleIds.Contains("R-MASS-MODIFY") && mass.Severity >= Severity.Medium,
        mass is null ? "no detection" : $"{mass.Severity} {string.Join(",", mass.RuleIds)}");

    var ransomware = Run(
        Many(FileEventKind.Modified, 60, entropy: 7.95)
            .Concat(Enumerable.Range(0, 60).Select(i =>
                Act(FileEventKind.Renamed, $@"C:\Docs\f{i}.docx.locked", 7.95, $@"C:\Docs\f{i}.docx"))), 3500, null, out _);
    Check("renames to .locked with random-looking content raise a critical alert",
        ransomware is not null && ransomware.Severity == Severity.Critical,
        ransomware is null ? "no detection" : $"{ransomware.Severity} score {ransomware.Score}");
    Check("  ...hitting extension, entropy and suspicious-extension rules",
        ransomware is not null && new[] { "R-EXT-CHANGE", "R-SUSPICIOUS-EXT", "R-ENTROPY" }.All(ransomware.RuleIds.Contains));
    Check("  ...and suggests acting on the responsible process", ransomware?.SuggestsProcessAction == true);
    Check("  ...and lists affected files", ransomware is not null && ransomware.AffectedFiles.Count >= 60);

    var zips = Run(Many(FileEventKind.Modified, 50, ext: ".zip", entropy: 7.99), 1500, null, out var zipMetrics);
    Check("compressed files (.zip) with high entropy are not counted as encryption", zipMetrics.HighEntropy == 0, $"HighEntropy={zipMetrics.HighEntropy}");
    Check("  ...and 50 modified files alone stay below alert level", zips is null);

    var notes = Run(new[]
    {
        Act(FileEventKind.Created, @"C:\Docs\HOW_TO_DECRYPT_FILES.txt"),
        Act(FileEventKind.Created, @"C:\Docs\Sub\!!!README!!!.html"),
    }, 3500, null, out _);
    Check("two ransom-note style files raise an alert with R-RANSOM-NOTE",
        notes is not null && notes.RuleIds.Contains("R-RANSOM-NOTE"));

    var delMass = Run(Many(FileEventKind.Deleted, 120), 3500, null, out _);
    Check("120 deletions alone (20 points) stay below alert level", delMass is null);

    Console.WriteLine("\n== Detection engine (decoy files) ==");
    var created = Run(new[] { Act(FileEventKind.Created, @"C:\Docs\_budget_2024.xlsx", honey: true) }, 1500, null, out _);
    Check("creating a decoy file does not raise an alert", created is null);

    var sw = System.Diagnostics.Stopwatch.StartNew();
    var decoy = Run(new[] { Act(FileEventKind.Modified, @"C:\Docs\_budget_2024.xlsx", 7.9, honey: true) }, 3500, null, out _);
    sw.Stop();
    Check("modifying a decoy file raises a critical 'Decoy file triggered' alert",
        decoy is not null && decoy.Severity == Severity.Critical && decoy.Title == "Decoy file triggered" &&
        decoy.RuleIds.Contains("R-HONEYPOT"), decoy is null ? "no detection" : $"{decoy.Severity} {decoy.Title}");
    Check("  ...immediately, not on the next 1 s tick", sw.ElapsedMilliseconds < 900, $"{sw.ElapsedMilliseconds} ms");
    Check("  ...and the decoy is listed as affected", decoy is not null && decoy.AffectedFiles.Contains(@"C:\Docs\_budget_2024.xlsx"));

    Console.WriteLine("\n== ML classifier ==");
    var missing = new ThreatClassifier();
    missing.Load(Path.Combine(tmp, "no_model.json"));
    Check("without a model file the classifier is off and scores 0", !missing.Available && missing.Score(new Dictionary<string, double>()) == 0);

    var badModelPath = Path.Combine(tmp, "bad.json");
    File.WriteAllText(badModelPath, "{ not json");
    var bad = new ThreatClassifier();
    bad.Load(badModelPath);
    Check("a corrupt model file is rejected without crashing", !bad.Available && bad.Description.StartsWith("Model could not be loaded"));

    var modelPath = Path.Combine(tmp, "model.json");
    File.WriteAllText(modelPath, JsonSerializer.Serialize(new
    {
        bias = -8.0,
        trained_on = "unit test",
        weights = new Dictionary<string, double> { ["modified"] = 5.0 }
    }));
    var model = new ThreatClassifier();
    model.Load(modelPath);
    Check("a valid model file loads", model.Available && model.Description.Contains("unit test"), model.Description);
    var s5 = model.Score(new Dictionary<string, double> { ["modified"] = 5 });
    var s50 = model.Score(new Dictionary<string, double> { ["modified"] = 50 });
    Check("more suspicious activity gives a higher score, always within 0-100", s50 > s5 && s5 is > 0 and < 100 && s50 <= 100, $"{s5:0.0} vs {s50:0.0}");

    var mlOnly = Run(Many(FileEventKind.Modified, 10), 3500, model, out _);
    Check("a very confident model can raise an alert when no rule fires",
        mlOnly is not null && mlOnly.RuleIds.Contains("R-ML"), mlOnly is null ? "no detection" : string.Join(",", mlOnly.RuleIds));

    var pessimist = new ThreatClassifier();
    var pessimistPath = Path.Combine(tmp, "pessimist.json");
    File.WriteAllText(pessimistPath, JsonSerializer.Serialize(new
    {
        bias = -50.0,
        weights = new Dictionary<string, double> { ["honeypot"] = -5.0 }
    }));
    pessimist.Load(pessimistPath);
    var stillCritical = Run(new[] { Act(FileEventKind.Modified, @"C:\Docs\_decoy.docx", 7.9, honey: true) }, 3500, pessimist, out _);
    Check("the model can never talk the rules out of a decoy alert", stillCritical?.Severity == Severity.Critical);

    // ------------------------------------------------------------------ file integrity
    Console.WriteLine("\n== File integrity monitoring ==");
    var protectedRoot = Path.Combine(tmp, "protected");
    Directory.CreateDirectory(Path.Combine(protectedRoot, "sub"));
    string Write(string rel, string text)
    {
        var p = Path.Combine(protectedRoot, rel.Replace('\\', Path.DirectorySeparatorChar));
        File.WriteAllText(p, text);
        return p;
    }

    var fa = Write("a.txt", "alpha content " + new string('a', 500));
    var fb = Write("b.txt", "bravo content " + new string('b', 500));
    var fc = Write(@"sub\c.txt", "charlie content " + new string('c', 500));
    var fd = Write("d.txt", "delta content " + new string('d', 500));

    var baseline = IntegrityScanner.BuildSnapshot(new[] { protectedRoot });
    Check("baseline hashes every file", baseline.Files.Count == 4, $"{baseline.Files.Count} files");
    Check("hashes are SHA-256 (64 hex chars)", baseline.Files.Values.All(f => f.Sha256.Length == 64));
    Check("an unchanged folder compares clean", !IntegrityScanner.Compare(baseline, IntegrityScanner.BuildSnapshot(new[] { protectedRoot })).HasChanges);

    File.WriteAllText(fa, "tampered " + new string('x', 500));                         // modified
    File.Delete(fb);                                                                    // deleted
    File.Move(fc, Path.Combine(protectedRoot, "sub", "c.txt.locked"));                  // renamed
    var fe = Write("e.txt", "echo content " + new string('e', 500));                    // added

    var current = IntegrityScanner.BuildSnapshot(new[] { protectedRoot });
    var report = IntegrityScanner.Compare(baseline, current);
    Check("detects the modified file", report.Modified.SequenceEqual(new[] { fa }));
    Check("detects the deleted file", report.Deleted.SequenceEqual(new[] { fb }));
    Check("detects the renamed file by matching its hash",
        report.Renamed.Count == 1 && report.Renamed[0].Old == fc && report.Renamed[0].New.EndsWith("c.txt.locked"));
    Check("detects the new file", report.Added.SequenceEqual(new[] { fe }));
    Check("counts the untouched file as unchanged", report.Unchanged == 1);
    var rows = report.Flatten(baseline.Files, current.Files);
    Check("flattens to one row per change with old and new hashes",
        rows.Count == 4 && rows.First(r => r.Kind == "Modified").OldSha256 != rows.First(r => r.Kind == "Modified").NewSha256);

    // ------------------------------------------------------------------ backups and recovery
    Console.WriteLine("\n== Recovery points and restore ==");
    var docs = Path.Combine(tmp, "docs");
    Directory.CreateDirectory(Path.Combine(docs, "nested"));
    var originals = new Dictionary<string, string>();
    for (var i = 0; i < 6; i++)
    {
        var p = Path.Combine(docs, i % 2 == 0 ? "nested" : "", $"file{i}.txt");
        File.WriteAllText(p, $"original document {i} " + new string((char)('a' + i), 2000));
        originals[p] = IntegrityScanner.HashFile(p);
    }

    var store = new BackupStore(Path.Combine(tmp, "backups"));
    var p1 = store.CreateRecoveryPoint(new[] { docs }, 10 * 1024 * 1024, null, "first");
    Check("creates a recovery point containing every file", p1.Files.Count == 6 && store.ListPoints().Count == 1);
    var objectsBefore = Directory.EnumerateFiles(Path.Combine(store.Root, "objects"), "*", SearchOption.AllDirectories).Count();
    var verifyClean = store.VerifyPoint(p1.Id);
    Check("a fresh point verifies clean", verifyClean.Checked == 6 && verifyClean.Bad.Count == 0);

    Thread.Sleep(30);
    var p2 = store.CreateRecoveryPoint(new[] { docs }, 10 * 1024 * 1024, null, "second, nothing changed");
    var objectsAfter = Directory.EnumerateFiles(Path.Combine(store.Root, "objects"), "*", SearchOption.AllDirectories).Count();
    Check("an unchanged second point stores no duplicate data", objectsAfter == objectsBefore, $"{objectsBefore} -> {objectsAfter}");

    // Simulate an attack: overwrite four files with random bytes and rename one.
    var victims = originals.Keys.Take(4).ToList();
    foreach (var v in victims) File.WriteAllBytes(v, RandomNumberGenerator.GetBytes(3000));
    File.Delete(originals.Keys.Last());

    var restored = store.Restore(p2.Id, null, inPlace: true);
    Check("restores the overwritten and deleted files in place", restored.Restored == 5, $"restored {restored.Restored}");
    Check("verifies every restored file against its recorded hash", restored.Verified == restored.Restored && restored.Success);
    Check("every file matches its original content again", originals.All(kv => File.Exists(kv.Key) && IntegrityScanner.HashFile(kv.Key) == kv.Value));
    Check("files that were already correct are left alone", restored.AlreadyCurrent == 1, $"AlreadyCurrent={restored.AlreadyCurrent}");
    Check("the damaged versions are kept as evidence, not destroyed",
        Directory.Exists(Path.Combine(store.Root, "prerestore")) &&
        Directory.EnumerateFiles(Path.Combine(store.Root, "prerestore"), "*", SearchOption.AllDirectories).Count() == 4);

    var elsewhere = Path.Combine(tmp, "restored_copy");
    var copyResult = store.Restore(p1.Id, elsewhere, inPlace: false);
    Check("can restore to a separate folder", copyResult.Success && copyResult.Restored == 6 &&
        Directory.EnumerateFiles(elsewhere, "*", SearchOption.AllDirectories).Count() == 6);

    var anObject = Directory.EnumerateFiles(Path.Combine(store.Root, "objects"), "*", SearchOption.AllDirectories).First();
    var bytes = File.ReadAllBytes(anObject);
    bytes[0] ^= 0xFF;
    File.WriteAllBytes(anObject, bytes);
    var tamper = store.VerifyPoint(p2.Id);
    Check("detects a tampered backup object", tamper.Bad.Count == 1 && tamper.Bad[0].StartsWith("Corrupt"), string.Join(";", tamper.Bad));

    Thread.Sleep(30);
    var p3 = store.CreateRecoveryPoint(new[] { docs }, 10 * 1024 * 1024, null, "during incident", tainted: true);
    store.Prune(keep: 1);
    var remaining = store.ListPoints();
    Check("pruning keeps the newest point and the newest point not taken during an incident",
        remaining.Count == 2 && remaining.Any(p => p.Id == p3.Id) && remaining.Any(p => !p.Tainted),
        $"{remaining.Count} remain");
    Check("the store recognises its own files so watchers can ignore them", store.IsInternalPath(Path.Combine(store.Root, "objects", "x")) && !store.IsInternalPath(docs));

    // ------------------------------------------------------------------ reports
    Console.WriteLine("\n== Reports ==");
    var incident = new Incident
    {
        Id = 7, TimeUtc = DateTime.UtcNow, Severity = Severity.Critical, Score = 95,
        Title = "Decoy <script>alert(1)</script> triggered, \"quoted\"", Description = "details",
        RuleIds = "R-HONEYPOT,R-ENTROPY", ProcessId = 4242, ProcessName = "evil.exe", Status = "Contained"
    };
    var data = new ReportData
    {
        ProtectedFolders = { docs },
        Incidents = { new IncidentReport { Incident = incident, AffectedFiles = { @"C:\Docs\a.docx" },
            Actions = { new IncidentAction { IncidentId = 7, Action = "Process suspended", Detail = "PID 4242", TimeUtc = DateTime.UtcNow } },
            Recommendations = { "Disconnect from the network." } } },
        Integrity = report,
        GeneralAdvice = RecommendationEngine.General()
    };
    var html = ReportBuilder.BuildHtml(data);
    Check("HTML report names the incident, process and action",
        html.Contains("evil.exe") && html.Contains("Process suspended") && html.Contains("Disconnect from the network."));
    Check("HTML report escapes untrusted text (no raw <script>)", !html.Contains("<script>alert(1)</script>"));
    var csv = ReportBuilder.BuildCsv(data);
    Check("CSV report has a header row and quotes embedded quotes",
        csv.Split('\n')[0].Length > 5 && csv.Contains("\"\"quoted\"\""), csv.Split('\n')[0]);

    // ------------------------------------------------------------------ guard rails and guidance
    Console.WriteLine("\n== Safety guard rails ==");
    var none = Array.Empty<string>();
    Check("never acts on core system processes", ProcessSafety.WhyProtected(4, "System", null, none) is not null &&
        ProcessSafety.WhyProtected(900, "lsass.exe", null, none) is not null && ProcessSafety.WhyProtected(901, "svchost", null, none) is not null);
    Check("never acts on WinShield itself", ProcessSafety.WhyProtected(Environment.ProcessId, "winshield", null, none) is not null);
    Check("never acts on processes the user trusts", ProcessSafety.WhyProtected(5000, "Notepad++.exe", null, new[] { "notepad++" }) is not null);
    Check("allows action on an unknown process in a temp folder",
        ProcessSafety.WhyProtected(5001, "locker.exe", Path.Combine(Path.GetTempPath(), "locker.exe"), none) is null);
    Check("flags temp folders as user-writable (typical malware location)", ProcessSafety.IsUserWritableLocation(Path.Combine(Path.GetTempPath(), "x.exe")));
    Check("recognises script hosts", ProcessSafety.IsScriptHost("PowerShell.exe") && !ProcessSafety.IsScriptHost("notepad.exe"));

    var high = new Incident { Severity = Severity.High, RuleIds = "R-HONEYPOT,R-MASS-MODIFY", ProcessName = "locker.exe", ProcessId = 99 };
    var tipsOpen = RecommendationEngine.ForIncident(high, Array.Empty<IncidentAction>(), networkIsolated: false);
    var tipsIsolated = RecommendationEngine.ForIncident(high, Array.Empty<IncidentAction>(), networkIsolated: true);
    Check("tells the user to disconnect when the network is still up", tipsOpen.Any(t => t.StartsWith("Disconnect")));
    Check("does not repeat that advice once isolated", !tipsIsolated.Any(t => t.StartsWith("Disconnect")));
    Check("explains an un-stopped process and mentions the decoy", tipsOpen.Any(t => t.Contains("locker.exe") && t.Contains("not stopped")) && tipsOpen.Any(t => t.Contains("decoy")));
    var contained = RecommendationEngine.ForIncident(high,
        new[] { new IncidentAction { Action = "Process suspended", Success = true } }, true);
    Check("changes the advice once the process was contained", contained.Any(t => t.Contains("was contained")));
    Check("provides general advice and a recovery checklist", RecommendationEngine.General().Count >= 5 && RecommendationEngine.RecoveryGuidance().Count >= 5);
}
finally
{
    try { Directory.Delete(tmp, recursive: true); } catch { /* temp cleanup only */ }
}

Console.WriteLine($"\n{total - failures} of {total} checks passed.");
return failures == 0 ? 0 : 1;
