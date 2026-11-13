using System.Security.Cryptography;
using WinShield.Core;
using WinShield.Data;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>Moves suspicious executables into a locked-away folder under a harmless name, and can restore them.</summary>
public sealed class QuarantineService
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".jar", ".msi"
    };

    private readonly ProtectionRepository _repo;

    public QuarantineService(ProtectionRepository repo) => _repo = repo;

    public (bool Ok, string Message, QuarantineItem? Item) Quarantine(string path, long? incidentId, string reason)
    {
        try
        {
            if (!File.Exists(path)) return (false, "The file no longer exists.", null);

            if (!ExecutableExtensions.Contains(Path.GetExtension(path)))
                return (false, "Only programs and scripts can be quarantined (.exe, .dll, .bat, .ps1, ...).", null);

            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (AppPaths.IsUnder(path, windows))
                return (false, "Files in the Windows folder are never quarantined automatically.", null);

            if (AppPaths.IsUnder(path, AppContext.BaseDirectory))
                return (false, "WinShield will not quarantine its own files.", null);

            var sha = HashFile(path);
            AppPaths.EnsureAll();
            var destination = Path.Combine(AppPaths.Quarantine, Guid.NewGuid().ToString("N") + ".quar");

            try
            {
                File.Move(path, destination);
            }
            catch (IOException)
            {
                return (false, "The file is in use. Terminate the process first, then quarantine the file.", null);
            }

            var item = new QuarantineItem
            {
                OriginalPath = path,
                QuarantinePath = destination,
                Sha256 = sha,
                TimeUtc = DateTime.UtcNow,
                IncidentId = incidentId,
                Reason = reason
            };
            item.Id = _repo.AddQuarantine(item);
            return (true, $"Quarantined {Path.GetFileName(path)} (SHA-256 {sha[..16]}...).", item);
        }
        catch (UnauthorizedAccessException)
        {
            return (false, "Access denied. Run WinShield as administrator.", null);
        }
        catch (Exception ex)
        {
            return (false, $"Quarantine failed: {ex.Message}", null);
        }
    }

    public (bool Ok, string Message) Restore(QuarantineItem item)
    {
        try
        {
            if (item.Restored) return (false, "This item was already restored.");
            if (!File.Exists(item.QuarantinePath)) return (false, "The quarantined file is missing.");
            if (File.Exists(item.OriginalPath)) return (false, "A file already exists at the original location.");

            Directory.CreateDirectory(Path.GetDirectoryName(item.OriginalPath)!);
            File.Move(item.QuarantinePath, item.OriginalPath);
            _repo.MarkQuarantineRestored(item.Id);
            return (true, $"Restored {item.OriginalPath}. Only do this if you are sure the file is safe.");
        }
        catch (Exception ex)
        {
            return (false, $"Restore failed: {ex.Message}");
        }
    }

    public (bool Ok, string Message) Delete(QuarantineItem item)
    {
        try
        {
            if (File.Exists(item.QuarantinePath)) File.Delete(item.QuarantinePath);
            _repo.DeleteQuarantine(item.Id);
            return (true, "Deleted the quarantined file permanently.");
        }
        catch (Exception ex)
        {
            return (false, $"Delete failed: {ex.Message}");
        }
    }

    internal static string HashFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        return Convert.ToHexString(SHA256.HashData(stream));
    }
}
