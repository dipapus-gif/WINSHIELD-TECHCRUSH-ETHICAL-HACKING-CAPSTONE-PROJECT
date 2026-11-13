using System.Diagnostics;
using WinShield.Core;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Samples every running process every two seconds (disk write rate and CPU) and flags programs that
/// write heavily, burn CPU while writing, or do so from a user-writable location.
/// </summary>
public sealed class ProcessBehaviorMonitor : IDisposable
{
    private sealed class Sample
    {
        public ulong WriteBytes;
        public long CpuTicks;
        public long Stamp;
        public long Created;
        public int Hits;
    }

    private readonly record struct WriterEntry(DateTime TimeUtc, int Pid, string Name, double MBps);

    private readonly Func<AppSettings> _settings;
    private readonly ProcessController _controller;
    private readonly Dictionary<int, Sample> _previous = new();
    private readonly List<WriterEntry> _writers = new();
    private readonly object _writerLock = new();

    private Timer? _timer;
    private int _busy;
    private volatile IReadOnlyList<SuspiciousProcess> _current = Array.Empty<SuspiciousProcess>();

    public ProcessBehaviorMonitor(Func<AppSettings> settings, ProcessController controller)
    {
        _settings = settings;
        _controller = controller;
    }

    public event Action<IReadOnlyList<SuspiciousProcess>>? Updated;

    public IReadOnlyList<SuspiciousProcess> Current => _current;

    public void Start()
    {
        Stop();
        _timer = new Timer(_ => Tick(), null, 2000, 2000);
    }

    public void Stop()
    {
        _timer?.Dispose();
        _timer = null;
        _previous.Clear();
        _current = Array.Empty<SuspiciousProcess>();
    }

    /// <summary>The heaviest recent writer that is not trusted or protected. Used to attribute file activity.</summary>
    public ProcessRef? TopWriter(TimeSpan window, double minMBps)
    {
        var s = _settings();
        var cutoff = DateTime.UtcNow - window;

        WriterEntry[] entries;
        lock (_writerLock) entries = _writers.Where(w => w.TimeUtc >= cutoff && w.MBps >= minMBps).ToArray();

        foreach (var best in entries.OrderByDescending(w => w.MBps))
        {
            var path = Win32.TryGetProcessPath(best.Pid);
            if (path is null) continue; // already gone
            if (ProcessSafety.WhyProtected(best.Pid, best.Name, path, s.TrustedProcesses) is not null) continue;
            return new ProcessRef(best.Pid, best.Name, path, "Medium");
        }
        return null;
    }

    private void Tick()
    {
        if (Interlocked.Exchange(ref _busy, 1) == 1) return;
        try
        {
            var s = _settings();
            var stamp = Stopwatch.GetTimestamp();
            var seen = new HashSet<int>();
            var found = new List<SuspiciousProcess>();
            var newWriters = new List<WriterEntry>();

            foreach (var process in Process.GetProcesses())
            {
                try
                {
                    var pid = process.Id;
                    if (pid <= 4 || pid == Environment.ProcessId) continue;

                    var handle = Win32.OpenProcess(Win32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
                    if (handle == IntPtr.Zero) continue;

                    try
                    {
                        if (!Win32.GetProcessIoCounters(handle, out var io)) continue;
                        if (!Win32.GetProcessTimes(handle, out var created, out _, out var kernel, out var user)) continue;

                        seen.Add(pid);
                        var cpuTicks = kernel + user;

                        if (!_previous.TryGetValue(pid, out var prev) || prev.Created != created)
                        {
                            _previous[pid] = new Sample
                            {
                                WriteBytes = io.WriteTransferCount, CpuTicks = cpuTicks, Stamp = stamp, Created = created
                            };
                            continue;
                        }

                        var seconds = (stamp - prev.Stamp) / (double)Stopwatch.Frequency;
                        if (seconds < 0.2) continue;

                        var written = (double)io.WriteTransferCount - prev.WriteBytes;
                        var mbps = Math.Max(0, written) / seconds / 1048576.0;
                        var cpu = (cpuTicks - prev.CpuTicks) / 1e7 / seconds / Environment.ProcessorCount * 100.0;

                        prev.WriteBytes = io.WriteTransferCount;
                        prev.CpuTicks = cpuTicks;
                        prev.Stamp = stamp;
                        prev.Hits = mbps >= s.SuspiciousWriteMBps / 3 ? prev.Hits + 1 : 0;

                        if (mbps < 3) continue;

                        var name = process.ProcessName;
                        if (s.TrustedProcesses.Contains(ProcessSafety.NormalizeName(name))) continue;

                        var path = Win32.TryGetProcessPath(pid);
                        if (mbps >= 5) newWriters.Add(new WriterEntry(DateTime.UtcNow, pid, name, mbps));

                        var suspicious = Rate(s, name, path, mbps, cpu, prev.Hits);
                        if (suspicious is not null)
                        {
                            suspicious.Pid = pid;
                            suspicious.IsSuspended = _controller.Suspended.ContainsKey(pid);
                            found.Add(suspicious);
                        }
                    }
                    finally
                    {
                        Win32.CloseHandle(handle);
                    }
                }
                catch
                {
                    // process exited or is not accessible
                }
                finally
                {
                    process.Dispose();
                }
            }

            foreach (var stale in _previous.Keys.Where(k => !seen.Contains(k)).ToList())
                _previous.Remove(stale);

            // Suspended processes stop writing, so keep them on the list until the user decides.
            foreach (var (pid, name) in _controller.Suspended)
            {
                if (found.Any(f => f.Pid == pid)) continue;
                found.Add(new SuspiciousProcess
                {
                    Pid = pid, Name = name, Score = 100, IsSuspended = true,
                    Path = Win32.TryGetProcessPath(pid), Reasons = "Suspended by WinShield"
                });
            }

            lock (_writerLock)
            {
                _writers.AddRange(newWriters);
                var cutoff = DateTime.UtcNow.AddSeconds(-60);
                _writers.RemoveAll(w => w.TimeUtc < cutoff);
            }

            _current = found.OrderByDescending(f => f.Score).Take(20).ToList();
            Updated?.Invoke(_current);
        }
        catch
        {
            // sampling is best effort
        }
        finally
        {
            Interlocked.Exchange(ref _busy, 0);
        }
    }

    private static SuspiciousProcess? Rate(AppSettings s, string name, string? path, double mbps, double cpu, int hits)
    {
        double score = 0;
        var reasons = new List<string>();

        if (mbps >= s.SuspiciousWriteMBps)
        {
            score += 40;
            reasons.Add($"writing {mbps:0.0} MB/s to disk");
        }
        else if (mbps >= s.SuspiciousWriteMBps / 3)
        {
            score += 15;
            reasons.Add($"writing {mbps:0.0} MB/s to disk");
        }

        if (cpu >= 40 && mbps >= 5)
        {
            score += 20;
            reasons.Add($"{cpu:0}% CPU while writing");
        }

        if (ProcessSafety.IsUserWritableLocation(path) && mbps >= 3)
        {
            score += 25;
            reasons.Add("runs from a user-writable folder");
        }

        if (hits >= 2)
        {
            score += 15;
            reasons.Add("sustained activity");
        }

        if (path is not null)
        {
            var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (AppPaths.IsUnder(path, windows)) score *= 0.3;
        }

        if (score < 30) return null;

        return new SuspiciousProcess
        {
            Name = name,
            Path = path,
            WriteMBps = mbps,
            CpuPercent = cpu,
            Score = Math.Min(100, Math.Round(score)),
            Reasons = string.Join("; ", reasons)
        };
    }

    public void Dispose() => Stop();
}
