using System.Security.Cryptography;
using System.Text;
using WinShield.Core;
using WinShield.Data;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Plants decoy files in the protected folders. Real users never touch them, so any change, rename or delete
/// is a strong ransomware signal. Decoys are plain low-entropy files with a clear notice inside.
/// </summary>
public sealed class HoneypotService
{
    // Names sort first and last, so alphabetical encryptors hit a decoy early.
    private static readonly string[] DecoyNames =
    {
        "!0_Account_Passwords_Backup.xlsx",
        "!0_Tax_Records_2025.docx",
        "zzz_Private_Photos_Archive.pdf"
    };

    private readonly ProtectionRepository _repo;
    private readonly HashSet<string> _paths = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();

    public HoneypotService(ProtectionRepository repo) => _repo = repo;

    public void Load()
    {
        var saved = _repo.GetHoneypots();
        lock (_lock)
        {
            _paths.Clear();
            foreach (var h in saved) _paths.Add(h.FilePath);
        }
    }

    public bool IsHoneypot(string path)
    {
        lock (_lock) return _paths.Contains(path);
    }

    public int Count
    {
        get { lock (_lock) return _paths.Count; }
    }

    /// <summary>Creates any missing decoys in each protected folder and in up to three of its sub-folders.</summary>
    public int Deploy(IEnumerable<string> folders)
    {
        var created = 0;
        foreach (var root in folders.Where(Directory.Exists))
        {
            var targets = new List<(string Dir, string[] Names)> { (root, DecoyNames) };

            try
            {
                var subs = Directory.EnumerateDirectories(root)
                    .Where(d => !new DirectoryInfo(d).Attributes.HasFlag(FileAttributes.Hidden) &&
                                !new DirectoryInfo(d).Attributes.HasFlag(FileAttributes.System))
                    .OrderBy(d => d, StringComparer.OrdinalIgnoreCase)
                    .Take(3);
                foreach (var sub in subs)
                    targets.Add((sub, new[] { DecoyNames[0], DecoyNames[2] }));
            }
            catch
            {
                // sub-folders are optional
            }

            foreach (var (dir, names) in targets)
            {
                foreach (var name in names)
                {
                    var path = Path.Combine(dir, name);
                    try
                    {
                        if (!File.Exists(path))
                        {
                            File.WriteAllBytes(path, BuildContent(name));
                            created++;
                        }

                        var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
                        _repo.AddHoneypot(path, hash, root);
                        lock (_lock) _paths.Add(path);
                    }
                    catch
                    {
                        // read-only or protected location: skip this decoy
                    }
                }
            }
        }
        return created;
    }

    /// <summary>Deletes all decoys. Used when protection is switched off for good or the folders change.</summary>
    public int Remove()
    {
        var removed = 0;
        foreach (var h in _repo.GetHoneypots())
        {
            try
            {
                if (File.Exists(h.FilePath)) { File.Delete(h.FilePath); removed++; }
            }
            catch
            {
                // leave it; it will show as in use
            }
            _repo.RemoveHoneypot(h.FilePath);
        }
        lock (_lock) _paths.Clear();
        return removed;
    }

    public List<HoneypotFile> ListWithStatus()
    {
        var list = _repo.GetHoneypots();
        foreach (var h in list)
        {
            try
            {
                if (!File.Exists(h.FilePath)) { h.Status = "Missing"; continue; }
                var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(h.FilePath)));
                h.Status = hash == h.Sha256 ? "Intact" : "Modified";
            }
            catch
            {
                h.Status = "Unreadable";
            }
        }
        return list;
    }

    private static byte[] BuildContent(string name)
    {
        var sb = new StringBuilder();
        sb.AppendLine("WinShield decoy file");
        sb.AppendLine($"Name: {name}");
        sb.AppendLine("This file is a tripwire for ransomware protection. It contains no real data.");
        sb.AppendLine("Please do not open, edit, move or delete it. Remove decoys from the WinShield Honeypots tab.");
        sb.AppendLine();
        for (var i = 0; i < 400; i++)
            sb.AppendLine($"Decoy record {i:0000}: confidential entry placeholder text for monitoring purposes only.");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }
}
