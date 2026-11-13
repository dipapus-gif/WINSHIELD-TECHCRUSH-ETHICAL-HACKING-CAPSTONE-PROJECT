namespace WinShield.Core;

/// <summary>Well-known folders used by WinShield.</summary>
public static class AppPaths
{
    public static string Root { get; private set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WinShield");

    /// <summary>Case rules for comparing file paths on this operating system.</summary>
    public static StringComparison PathComparison =>
        OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;

    /// <summary>Points WinShield's data folder somewhere else. Used by the self-tests only.</summary>
    public static void OverrideRoot(string root) => Root = Path.GetFullPath(root);

    public static string Database => Path.Combine(Root, "winshield.db");
    public static string SettingsFile => Path.Combine(Root, "settings.json");
    public static string ModelFile => Path.Combine(Root, "model.json");
    public static string PersistenceBaseline => Path.Combine(Root, "persistence_baseline.json");
    public static string Quarantine => Path.Combine(Root, "Quarantine");
    public static string Evidence => Path.Combine(Root, "Evidence");
    public static string DefaultBackups => Path.Combine(Root, "Backups");

    public static string Reports => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "WinShield Reports");

    /// <summary>True for WinShield's own data and report folders, which are never scanned, hashed or decoyed.</summary>
    public static bool IsInternal(string path) => IsUnder(path, Root) || IsUnder(path, Reports);

    public static void EnsureAll()
    {
        Directory.CreateDirectory(Root);
        Directory.CreateDirectory(Quarantine);
        Directory.CreateDirectory(Evidence);
    }

    private static string WithSeparator(string path)
    {
        var full = Path.GetFullPath(path);
        return full.EndsWith(Path.DirectorySeparatorChar) ? full : full + Path.DirectorySeparatorChar;
    }

    /// <summary>True when <paramref name="path"/> is the folder itself or inside it.</summary>
    public static bool IsUnder(string path, string folder)
    {
        if (string.IsNullOrWhiteSpace(path) || string.IsNullOrWhiteSpace(folder)) return false;
        try
        {
            var p = WithSeparator(path);
            var f = WithSeparator(folder);
            return p.StartsWith(f, PathComparison);
        }
        catch
        {
            return false;
        }
    }
}
