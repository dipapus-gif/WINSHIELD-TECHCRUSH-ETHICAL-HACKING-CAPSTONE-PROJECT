namespace WinShield.Services;

/// <summary>Shannon entropy of file contents. Encrypted data sits close to 8 bits per byte.</summary>
public static class EntropyCalculator
{
    // File types that are legitimately high-entropy (already compressed or zip-based).
    private static readonly HashSet<string> HighEntropyTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        ".zip", ".7z", ".rar", ".gz", ".bz2", ".xz", ".zst", ".tgz", ".cab", ".iso",
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".avif",
        ".mp3", ".mp4", ".m4a", ".m4v", ".mkv", ".avi", ".mov", ".wmv", ".flac", ".ogg", ".opus", ".webm",
        ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".odp", ".epub", ".pdf",
        ".jar", ".apk", ".msi", ".nupkg", ".vsix"
    };

    [ThreadStatic] private static byte[]? _buffer;

    public static bool IsExpectedHighEntropy(string extension) => HighEntropyTypes.Contains(extension);

    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0;

        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;

        double entropy = 0;
        double length = data.Length;
        for (var i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            var p = counts[i] / length;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }

    /// <summary>
    /// Entropy of the first <paramref name="maxBytes"/> of a file, or -1 when the file cannot be read or is too
    /// small for a meaningful sample (under 1 KB).
    /// </summary>
    public static double SampleFile(string path, int maxBytes = 65536)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.SequentialScan);

            _buffer ??= new byte[65536];
            var limit = Math.Min(maxBytes, _buffer.Length);
            var total = 0;
            while (total < limit)
            {
                var n = fs.Read(_buffer, total, limit - total);
                if (n <= 0) break;
                total += n;
            }

            return total < 1024 ? -1 : Shannon(_buffer.AsSpan(0, total));
        }
        catch
        {
            return -1;
        }
    }
}
