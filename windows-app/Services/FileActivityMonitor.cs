using System.Collections.Concurrent;
using System.Threading.Channels;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Watches the protected folders and turns raw file-system notifications into <see cref="FileActivity"/> records.
/// Watcher threads only enqueue; a single worker thread does the slower work (size, entropy) so the
/// operating system's notification buffer is drained quickly.
/// </summary>
public sealed class FileActivityMonitor : IDisposable
{
    private readonly record struct RawEvent(DateTime TimeUtc, FileEventKind Kind, string FullPath, string? OldPath);

    private readonly List<FileSystemWatcher> _watchers = new();
    private readonly Channel<RawEvent> _channel = Channel.CreateUnbounded<RawEvent>(
        new UnboundedChannelOptions { SingleReader = true });
    private readonly ConcurrentDictionary<string, long> _recentModified = new(StringComparer.OrdinalIgnoreCase);
    private readonly Func<string, bool> _isHoneypot;
    private readonly Func<string, bool> _isIgnored;

    private CancellationTokenSource? _cts;
    private Task? _worker;

    public FileActivityMonitor(Func<string, bool> isHoneypot, Func<string, bool> isIgnored)
    {
        _isHoneypot = isHoneypot;
        _isIgnored = isIgnored;
    }

    public event Action<FileActivity>? ActivityObserved;

    /// <summary>Raised when the OS notification buffer overflowed (a sign of very heavy file activity).</summary>
    public event Action<string>? WatcherError;

    public bool IsRunning => _worker is not null;

    public IReadOnlyList<string> WatchedFolders => _watchers.Select(w => w.Path).ToList();

    public void Start(IEnumerable<string> folders)
    {
        Stop();

        foreach (var folder in folders.Where(Directory.Exists))
        {
            try
            {
                var watcher = new FileSystemWatcher(folder)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName |
                                   NotifyFilters.LastWrite | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024
                };

                watcher.Created += (_, e) => Enqueue(FileEventKind.Created, e.FullPath, null);
                watcher.Changed += (_, e) => Enqueue(FileEventKind.Modified, e.FullPath, null);
                watcher.Deleted += (_, e) => Enqueue(FileEventKind.Deleted, e.FullPath, null);
                watcher.Renamed += (_, e) => Enqueue(FileEventKind.Renamed, e.FullPath, e.OldFullPath);
                watcher.Error += (_, e) => WatcherError?.Invoke(e.GetException().Message);
                watcher.EnableRaisingEvents = true;
                _watchers.Add(watcher);
            }
            catch (Exception ex)
            {
                WatcherError?.Invoke($"Could not watch {folder}: {ex.Message}");
            }
        }

        _cts = new CancellationTokenSource();
        var token = _cts.Token;
        _worker = Task.Run(() => RunAsync(token));
    }

    public void Stop()
    {
        foreach (var w in _watchers)
        {
            w.EnableRaisingEvents = false;
            w.Dispose();
        }
        _watchers.Clear();

        _cts?.Cancel();
        try { _worker?.Wait(TimeSpan.FromSeconds(2)); } catch { /* cancelled */ }
        _cts?.Dispose();
        _cts = null;
        _worker = null;
        _recentModified.Clear();
    }

    private void Enqueue(FileEventKind kind, string fullPath, string? oldPath)
    {
        if (_isIgnored(fullPath)) return;

        // One write usually raises several Changed events: collapse them.
        if (kind == FileEventKind.Modified)
        {
            var now = Environment.TickCount64;
            if (_recentModified.TryGetValue(fullPath, out var last) && now - last < 300) return;
            if (_recentModified.Count > 20_000) _recentModified.Clear();
            _recentModified[fullPath] = now;
        }

        _channel.Writer.TryWrite(new RawEvent(DateTime.UtcNow, kind, fullPath, oldPath));
    }

    private async Task RunAsync(CancellationToken token)
    {
        try
        {
            await foreach (var raw in _channel.Reader.ReadAllAsync(token))
            {
                try
                {
                    var activity = Enrich(raw);
                    if (activity is not null) ActivityObserved?.Invoke(activity);
                }
                catch
                {
                    // A single bad event must never stop monitoring.
                }
            }
        }
        catch (OperationCanceledException)
        {
            // normal shutdown
        }
    }

    private FileActivity? Enrich(RawEvent raw)
    {
        long size = -1;
        double entropy = -1;

        if (raw.Kind != FileEventKind.Deleted)
        {
            // Folder events are not interesting; files that vanished again are skipped too.
            if (Directory.Exists(raw.FullPath)) return null;

            var info = new FileInfo(raw.FullPath);
            if (info.Exists)
            {
                size = info.Length;
                entropy = EntropyCalculator.SampleFile(raw.FullPath);
            }
            else if (raw.Kind == FileEventKind.Modified)
            {
                return null;
            }
        }

        return new FileActivity(raw.TimeUtc, raw.Kind, raw.FullPath, raw.OldPath, size, entropy, _isHoneypot(raw.FullPath));
    }

    public void Dispose() => Stop();
}
