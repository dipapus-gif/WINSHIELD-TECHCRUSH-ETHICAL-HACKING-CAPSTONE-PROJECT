using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using WinShield.Core;

namespace WinShield.Services;

/// <summary>Suspends, resumes and terminates processes. Suspending is reversible; killing is not.</summary>
public sealed class ProcessController
{
    private readonly ConcurrentDictionary<int, string> _suspended = new();

    public IReadOnlyDictionary<int, string> Suspended => _suspended;

    public event Action? SuspendedChanged;

    /// <summary>Guards against PID reuse: the process must still be running the executable we identified.</summary>
    private static string? CheckIdentity(int pid, string? expectedPath)
    {
        if (string.IsNullOrEmpty(expectedPath)) return null;
        var current = Win32.TryGetProcessPath(pid);
        if (current is null) return "the process is no longer running";
        return string.Equals(current, expectedPath, StringComparison.OrdinalIgnoreCase)
            ? null
            : "the process id now belongs to a different program";
    }

    public (bool Ok, string Message) Suspend(int pid, string name, string? expectedPath = null)
    {
        var problem = CheckIdentity(pid, expectedPath);
        if (problem is not null) return (false, $"Not suspended: {problem}.");

        var handle = Win32.OpenProcess(Win32.PROCESS_SUSPEND_RESUME | Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero)
            return (false, $"Could not open {name} (PID {pid}), Windows error {Marshal.GetLastWin32Error()}. Run WinShield as administrator.");

        try
        {
            var status = Win32.NtSuspendProcess(handle);
            if (status != 0) return (false, $"Windows refused to suspend {name} (status 0x{status:X}).");

            _suspended[pid] = name;
            SuspendedChanged?.Invoke();
            return (true, $"Suspended {name} (PID {pid}). It can be resumed or terminated from the incident page.");
        }
        finally
        {
            Win32.CloseHandle(handle);
        }
    }

    public (bool Ok, string Message) Resume(int pid)
    {
        var name = _suspended.TryGetValue(pid, out var n) ? n : $"PID {pid}";
        var handle = Win32.OpenProcess(Win32.PROCESS_SUSPEND_RESUME, false, pid);
        if (handle == IntPtr.Zero)
        {
            _suspended.TryRemove(pid, out _);
            SuspendedChanged?.Invoke();
            return (false, $"{name} is no longer running or cannot be opened.");
        }

        try
        {
            var status = Win32.NtResumeProcess(handle);
            if (status != 0) return (false, $"Windows refused to resume {name} (status 0x{status:X}).");

            _suspended.TryRemove(pid, out _);
            SuspendedChanged?.Invoke();
            return (true, $"Resumed {name} (PID {pid}).");
        }
        finally
        {
            Win32.CloseHandle(handle);
        }
    }

    public int ResumeAll()
    {
        var count = 0;
        foreach (var pid in _suspended.Keys.ToList())
            if (Resume(pid).Ok) count++;
        return count;
    }

    public (bool Ok, string Message) Kill(int pid, string name, string? expectedPath = null)
    {
        var problem = CheckIdentity(pid, expectedPath);
        if (problem is not null) return (false, $"Not terminated: {problem}.");

        try
        {
            using var process = Process.GetProcessById(pid);
            process.Kill(entireProcessTree: true);
            process.WaitForExit(3000);
            _suspended.TryRemove(pid, out _);
            SuspendedChanged?.Invoke();
            return (true, $"Terminated {name} (PID {pid}) and its child processes.");
        }
        catch (ArgumentException)
        {
            return (false, $"{name} (PID {pid}) is no longer running.");
        }
        catch (Exception ex)
        {
            return (false, $"Could not terminate {name} (PID {pid}): {ex.Message}");
        }
    }
}
