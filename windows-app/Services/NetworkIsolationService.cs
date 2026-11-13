using WinShield.Core;

namespace WinShield.Services;

/// <summary>
/// Cuts the PC off from the network with two Windows Firewall block rules (inbound and outbound).
/// Block rules override allow rules, and removing the two rules restores the previous state exactly.
/// Needs administrator rights.
/// </summary>
public sealed class NetworkIsolationService
{
    private const string OutRule = "WinShield Isolation Out";
    private const string InRule = "WinShield Isolation In";

    public bool IsIsolated()
    {
        try
        {
            var (code, _) = ProcessRunner.Run("netsh", $"advfirewall firewall show rule name=\"{OutRule}\"", 10000);
            return code == 0;
        }
        catch
        {
            return false;
        }
    }

    public (bool Ok, string Message) Isolate()
    {
        if (!AdminHelper.IsAdministrator)
            return (false, "Network isolation needs administrator rights. Restart WinShield as administrator.");

        try
        {
            if (IsIsolated()) return (true, "The PC is already isolated from the network.");

            var (outCode, outText) = ProcessRunner.Run("netsh",
                $"advfirewall firewall add rule name=\"{OutRule}\" dir=out action=block enable=yes profile=any", 15000);
            var (inCode, inText) = ProcessRunner.Run("netsh",
                $"advfirewall firewall add rule name=\"{InRule}\" dir=in action=block enable=yes profile=any", 15000);

            if (outCode == 0 && inCode == 0)
                return (true, "Network isolated: all inbound and outbound traffic is blocked. Use 'Restore network' when it is safe.");

            Restore(); // do not leave a half-applied state behind
            return (false, $"Could not isolate the network. {outText.Trim()} {inText.Trim()}".Trim());
        }
        catch (Exception ex)
        {
            return (false, $"Network isolation failed: {ex.Message}");
        }
    }

    public (bool Ok, string Message) Restore()
    {
        if (!AdminHelper.IsAdministrator)
            return (false, "Restoring the network needs administrator rights.");

        try
        {
            ProcessRunner.Run("netsh", $"advfirewall firewall delete rule name=\"{OutRule}\"", 15000);
            ProcessRunner.Run("netsh", $"advfirewall firewall delete rule name=\"{InRule}\"", 15000);
            return IsIsolated()
                ? (false, "The isolation rules are still present. Remove 'WinShield Isolation' rules in Windows Firewall.")
                : (true, "Network access restored.");
        }
        catch (Exception ex)
        {
            return (false, $"Could not restore the network: {ex.Message}");
        }
    }
}
