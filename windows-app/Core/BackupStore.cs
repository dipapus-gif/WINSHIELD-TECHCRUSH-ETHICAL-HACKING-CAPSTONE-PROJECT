using System.Security.Cryptography;
using System.Text.Json;

namespace WinShield.Core;

public sealed class BackupEntry
{
    public string Root { get; set; } = "";
    public string RelativePath { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public long Size { get; set; }
    public long LastWriteTicksUtc { get; set; }
}

public sealed class BackupPoint
{
    public string Id { get; set; } = "";
    public DateTime CreatedUtc { get; set; }
    public string Note { get; set; } = "";
    public bool Tainted { get; set; }
    public int Skipped { get; set; }
    public long TotalBytes { get; set; }
    public List<string> Roots { get; set; } = new();
    public List<BackupEntry> Files { get; set; } = new();

    public DateTime CreatedLocal => CreatedUtc.ToLocalTime();
    public int FileCount => Files.Count;
    public string SizeText => $"{TotalBytes / 1048576.0:0.0} MB";
    public string StateText => Tainted ? "Created during an incident" : "OK";
}

public sealed class RestoreResult
{
    public int Restored { get; set; }
    public int AlreadyCurrent { get; set; }
    public int Verified { get; set; }
    public string Destination { get; set; } = "";
    public List<string> Failures { get; } = new();
    public bool Success => Failures.Count == 0;
}

/// <summary>
/// Content-addressed backup store. Each unique file content is stored once under objects/ (named by its
/// SHA-256), and every recovery point is a small manifest listing which hash belongs to which path.
/// That makes recovery points cheap, lets restores be verified, and means a later bad backup can never
/// overwrite an earlier good one.
/// </summary>
public sealed class BackupStore
{
    private readonly object _gate = new();
    private int _busy;
    private long _lastBusyEndTicks;

    public BackupStore(string root)
    {
        Root = Path.GetFullPath(root);
        Directory.CreateDirectory(PointsDir);
        Directory.CreateDirectory(ObjectsDir);
        Directory.CreateDirectory(TmpDir);
    }

    public string Root { get; }
    private string PointsDir => Path.Combine(Root, "points");
    private string ObjectsDir => Path.Combine(Root, "objects");
    private string TmpDir => Path.Combine(Root, "tmp");
    private string PrerestoreDir => Path.Combine(Root, "prerestore");

    /// <summary>True while the store is changing its own files (and for a few seconds after), so a deletion watcher can ignore them.</summary>
    public bool IsBusy =>
        Volatile.Read(ref _busy) > 0 ||
        DateTime.UtcNow.Ticks - Interlocked.Read(ref _lastBusyEndTicks) < TimeSpan.FromSeconds(3).Ticks;

    public bool IsInternalPath(string path)
    {
        var full = Path.GetFullPath(path);
        return full.StartsWith(Path.TrimEndingDirectorySeparator(Root) + Path.DirectorySeparatorChar, AppPaths.PathComparison);
    }

    private IDisposable EnterBusy()
    {
        Interlocked.Increment(ref _busy);
        return new BusyScope(this);
    }

    private sealed class BusyScope : IDisposable
    {
        private readonly BackupStore _store;
        public BusyScope(BackupStore store) => _store = store;
        public void Dispose()
        {
            Interlocked.Decrement(ref _store._busy);
            Interlocked.Exchange(ref _store._lastBusyEndTicks, DateTime.UtcNow.Ticks);
        }
    }

    private string ObjectPath(string hash) => Path.Combine(ObjectsDir, hash[..2], hash);
    private string ManifestPath(string id) => Path.Combine(PointsDir, id + ".json");

    public BackupPoint CreateRecoveryPoint(IEnumerable<string> roots, long maxFileBytes,
        Func<string, bool>? exclude = null, string note = "", bool tainted = false, CancellationToken ct = default)
    {
        lock (_gate)
        using (EnterBusy())
        {
            var previous = ListPoints().FirstOrDefault();
            var previousIndex = new Dictionary<string, BackupEntry>(StringComparer.OrdinalIgnoreCase);
            if (previous is not null)
                foreach (var e in previous.Files) previousIndex[e.Root + "|" + e.RelativePath] = e;

            var point = new BackupPoint
            {
                Id = $"{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid().ToString("N")[..4]}",
                CreatedUtc = DateTime.UtcNow,
                Note = note,
                Tainted = tainted
            };

            foreach (var rawRoot in roots)
            {
                var root = Path.GetFullPath(rawRoot);
                if (!Directory.Exists(root)) continue;
                point.Roots.Add(root);

                foreach (var file in IntegrityScanner.EnumerateFiles(root))
                {
                    ct.ThrowIfCancellationRequested();
                    if (IsInternalPath(file) || AppPaths.IsInternal(file) || (exclude?.Invoke(file) ?? false)) continue;

                    try
                    {
                        var info = new FileInfo(file);
                        if (info.Length > maxFileBytes) { point.Skipped++; continue; }

                        var relative = Path.GetRelativePath(root, file);
                        var mtime = info.LastWriteTimeUtc.Ticks;

                        BackupEntry entry;
                        if (previousIndex.TryGetValue(root + "|" + relative, out var old) &&
                            old.Size == info.Length && old.LastWriteTicksUtc == mtime && File.Exists(ObjectPath(old.Sha256)))
                        {
                            entry = old; // unchanged since the last point: reuse without reading the file
                        }
                        else
                        {
                            var (hash, bytes) = StoreObject(file);
                            entry = new BackupEntry { Root = root, RelativePath = relative, Sha256 = hash, Size = bytes, LastWriteTicksUtc = mtime };
                        }

                        point.Files.Add(entry);
                        point.TotalBytes += entry.Size;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                    {
                        point.Skipped++; // locked or unreadable right now
                    }
                }
            }

            WriteManifest(point);
            return point;
        }
    }

    private (string Hash, long Bytes) StoreObject(string file)
    {
        var tmp = Path.Combine(TmpDir, Guid.NewGuid().ToString("N"));
        try
        {
            string hash;
            long total = 0;
            using (var src = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 81920, FileOptions.SequentialScan))
            using (var dst = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920))
            using (var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
            {
                var buffer = new byte[81920];
                int n;
                while ((n = src.Read(buffer, 0, buffer.Length)) > 0)
                {
                    sha.AppendData(buffer, 0, n);
                    dst.Write(buffer, 0, n);
                    total += n;
                }
                hash = Convert.ToHexString(sha.GetHashAndReset()).ToLowerInvariant();
            }

            var target = ObjectPath(hash);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            if (File.Exists(target)) File.Delete(tmp);
            else File.Move(tmp, target);
            return (hash, total);
        }
        catch
        {
            try { if (File.Exists(tmp)) File.Delete(tmp); } catch (IOException) { }
            throw;
        }
    }

    private void WriteManifest(BackupPoint point)
    {
        var path = ManifestPath(point.Id);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(point));
        File.Move(tmp, path, overwrite: true);
    }

    /// <summary>All recovery points, newest first.</summary>
    public IReadOnlyList<BackupPoint> ListPoints()
    {
        var list = new List<BackupPoint>();
        if (!Directory.Exists(PointsDir)) return list;

        foreach (var file in Directory.EnumerateFiles(PointsDir, "*.json"))
        {
            try
            {
                var point = JsonSerializer.Deserialize<BackupPoint>(File.ReadAllText(file));
                if (point is not null) list.Add(point);
            }
            catch (JsonException) { }
            catch (IOException) { }
        }
        return list.OrderByDescending(p => p.CreatedUtc).ToList();
    }

    public BackupPoint? GetPoint(string id) => ListPoints().FirstOrDefault(p => p.Id == id);

    public void MarkTainted(string id)
    {
        var point = GetPoint(id);
        if (point is null) return;
        point.Tainted = true;
        using (EnterBusy()) WriteManifest(point);
    }

    /// <summary>
    /// Restores a recovery point. With <paramref name="inPlace"/> false, files go to a separate folder and
    /// nothing existing is touched. With true, missing or different files are restored over the originals,
    /// and anything that gets replaced is first moved into the store's prerestore folder.
    /// Every restored file is re-hashed and compared with the recorded hash.
    /// </summary>
    public RestoreResult Restore(string pointId, string? destinationFolder, bool inPlace, CancellationToken ct = default)
    {
        var point = GetPoint(pointId) ?? throw new InvalidOperationException($"Recovery point {pointId} was not found.");
        var result = new RestoreResult();

        using (EnterBusy())
        {
            var rootLabels = point.Roots.Select((r, i) =>
                (Root: r, Label: $"{i + 1}_{Sanitize(Path.GetFileName(Path.TrimEndingDirectorySeparator(r)))}")).ToDictionary(x => x.Root, x => x.Label);

            if (!inPlace)
            {
                destinationFolder ??= Path.Combine(Root, "restored", point.Id);
                Directory.CreateDirectory(destinationFolder);
                result.Destination = destinationFolder;
            }
            else
            {
                result.Destination = "original locations";
            }

            foreach (var entry in point.Files)
            {
                ct.ThrowIfCancellationRequested();
                var source = ObjectPath(entry.Sha256);
                var target = inPlace
                    ? Path.Combine(entry.Root, entry.RelativePath)
                    : Path.Combine(destinationFolder!, rootLabels.GetValueOrDefault(entry.Root, "root"), entry.RelativePath);

                try
                {
                    if (!File.Exists(source)) throw new IOException("backup object is missing");

                    if (File.Exists(target))
                    {
                        if (inPlace && IntegrityScanner.HashFile(target) == entry.Sha256)
                        {
                            result.AlreadyCurrent++;
                            continue;
                        }
                        if (inPlace)
                        {
                            var holding = Path.Combine(PrerestoreDir, point.Id);
                            Directory.CreateDirectory(holding);
                            File.Move(target, Path.Combine(holding, Guid.NewGuid().ToString("N")[..8] + "_" + Path.GetFileName(target)));
                        }
                    }

                    Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                    File.Copy(source, target, overwrite: true);
                    File.SetLastWriteTimeUtc(target, new DateTime(entry.LastWriteTicksUtc, DateTimeKind.Utc));
                    result.Restored++;

                    if (IntegrityScanner.HashFile(target) == entry.Sha256) result.Verified++;
                    else result.Failures.Add($"Hash mismatch after restore: {target}");
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    result.Failures.Add($"{target}: {ex.Message}");
                }
            }
        }
        return result;
    }

    /// <summary>Re-hashes every stored object a recovery point needs, to detect silent corruption or tampering.</summary>
    public (int Checked, List<string> Bad) VerifyPoint(string pointId)
    {
        var point = GetPoint(pointId) ?? throw new InvalidOperationException($"Recovery point {pointId} was not found.");
        var bad = new List<string>();
        var checkedCount = 0;

        using (EnterBusy())
        {
            foreach (var hash in point.Files.Select(f => f.Sha256).Distinct())
            {
                checkedCount++;
                var path = ObjectPath(hash);
                try
                {
                    if (!File.Exists(path)) bad.Add($"Missing object {hash[..12]}");
                    else if (IntegrityScanner.HashFile(path) != hash) bad.Add($"Corrupt object {hash[..12]}");
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    bad.Add($"Unreadable object {hash[..12]}");
                }
            }
        }
        return (checkedCount, bad);
    }

    /// <summary>
    /// Keeps the newest <paramref name="keep"/> points, always also keeps the newest point that was not
    /// created during an incident, then deletes stored objects nothing refers to any more.
    /// </summary>
    public int Prune(int keep)
    {
        lock (_gate)
        using (EnterBusy())
        {
            var points = ListPoints().ToList();
            var survivors = points.Take(Math.Max(1, keep)).ToList();
            var lastGood = points.FirstOrDefault(p => !p.Tainted);
            if (lastGood is not null && survivors.All(p => p.Id != lastGood.Id)) survivors.Add(lastGood);

            foreach (var doomed in points.Where(p => survivors.All(s => s.Id != p.Id)))
                File.Delete(ManifestPath(doomed.Id));

            var referenced = new HashSet<string>(survivors.SelectMany(p => p.Files).Select(f => f.Sha256));
            var deleted = 0;
            foreach (var file in Directory.EnumerateFiles(ObjectsDir, "*", SearchOption.AllDirectories))
            {
                if (referenced.Contains(Path.GetFileName(file))) continue;
                try { File.Delete(file); deleted++; }
                catch (IOException) { }
            }
            return deleted;
        }
    }

    private static string Sanitize(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) name = name.Replace(c, '_');
        return string.IsNullOrWhiteSpace(name) ? "root" : name;
    }
}
