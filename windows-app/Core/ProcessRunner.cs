using System.Diagnostics;
using System.Security.Principal;
using System.Text;

namespace WinShield.Core;

public static class ProcessRunner
{
    /// <summary>Runs a console program and returns its exit code and combined output.</summary>
    public static (int ExitCode, string Output) Run(string fileName, string arguments, int timeoutMs = 20000)
    {
        var psi = new ProcessStartInfo(fileName, arguments)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using var p = Process.Start(psi);
        if (p is null) return (-1, "Could not start the process.");

        var sb = new StringBuilder();
        p.OutputDataReceived += (_, e) => { if (e.Data != null) lock (sb) sb.AppendLine(e.Data); };
        p.ErrorDataReceived += (_, e) => { if (e.Data != null) lock (sb) sb.AppendLine(e.Data); };
        p.BeginOutputReadLine();
        p.BeginErrorReadLine();

        if (!p.WaitForExit(timeoutMs))
        {
            try { p.Kill(true); } catch { /* already gone */ }
            return (-2, sb + "\n[timed out]");
        }

        p.WaitForExit(); // flush the async readers
        return (p.ExitCode, sb.ToString());
    }

    /// <summary>Runs a PowerShell script using -EncodedCommand so quoting never breaks.</summary>
    public static (int ExitCode, string Output) RunPowerShell(string script, int timeoutMs = 30000)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return Run("powershell.exe", $"-NoProfile -NonInteractive -EncodedCommand {encoded}", timeoutMs);
    }

    public static string PowerShellQuote(string value) => "'" + value.Replace("'", "''") + "'";
}

public static class AdminHelper
{
    public static bool IsAdministrator
    {
        get
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }
    }
}
