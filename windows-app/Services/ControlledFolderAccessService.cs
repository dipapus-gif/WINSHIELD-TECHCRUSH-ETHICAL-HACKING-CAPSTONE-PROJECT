using WinShield.Core;

namespace WinShield.Services;

/// <summary>
/// Uses Microsoft Defender's built-in Controlled Folder Access to stop untrusted programs from writing to the
/// protected folders. This is the supported Windows way to restrict applications from protected directories.
/// </summary>
public sealed class ControlledFolderAccessService
{
    public string GetStatus()
    {
        try
        {
            var (code, output) = ProcessRunner.RunPowerShell("(Get-MpPreference).EnableControlledFolderAccess", 20000);
            if (code != 0) return "Unavailable (Defender not active or access denied)";
            return output.Trim() switch
            {
                "1" => "Enabled",
                "2" => "Audit mode",
                "0" => "Disabled",
                _ => "Unknown"
            };
        }
        catch
        {
            return "Unavailable";
        }
    }

    public (bool Ok, string Message) Enable(IEnumerable<string> folders)
    {
        if (!AdminHelper.IsAdministrator)
            return (false, "Controlled Folder Access needs administrator rights.");

        try
        {
            var script = "$ErrorActionPreference = 'Stop'; Set-MpPreference -EnableControlledFolderAccess Enabled;";
            foreach (var folder in folders.Where(Directory.Exists))
                script += $" Add-MpPreference -ControlledFolderAccessProtectedFolders {ProcessRunner.PowerShellQuote(folder)};";

            var (code, output) = ProcessRunner.RunPowerShell(script, 45000);
            return code == 0
                ? (true, "Controlled Folder Access is on: untrusted programs can no longer change files in the protected folders.")
                : (false, $"Defender refused the change. {output.Trim()}");
        }
        catch (Exception ex)
        {
            return (false, $"Could not enable Controlled Folder Access: {ex.Message}");
        }
    }

    public (bool Ok, string Message) Disable()
    {
        if (!AdminHelper.IsAdministrator)
            return (false, "Controlled Folder Access needs administrator rights.");

        try
        {
            var (code, output) = ProcessRunner.RunPowerShell(
                "$ErrorActionPreference = 'Stop'; Set-MpPreference -EnableControlledFolderAccess Disabled", 30000);
            return code == 0 ? (true, "Controlled Folder Access turned off.") : (false, output.Trim());
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}
