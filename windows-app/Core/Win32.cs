using System.Runtime.InteropServices;
using System.Text;

namespace WinShield.Core;

/// <summary>Thin P/Invoke layer for process control, I/O counters and file-lock lookups.</summary>
internal static class Win32
{
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint PROCESS_SUSPEND_RESUME = 0x0800;
    private const int ERROR_MORE_DATA = 234;

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetProcessIoCounters(IntPtr process, out IO_COUNTERS counters);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder name, ref int size);

    [DllImport("ntdll.dll")]
    public static extern int NtSuspendProcess(IntPtr process);

    [DllImport("ntdll.dll")]
    public static extern int NtResumeProcess(IntPtr process);

    public static string? TryGetProcessPath(int pid)
    {
        var handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024);
            var size = sb.Capacity;
            return QueryFullProcessImageName(handle, 0, sb, ref size) ? sb.ToString() : null;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    // ---- Restart Manager: which processes currently hold a file open? ----

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint sessionHandle, int flags, StringBuilder sessionKey);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint sessionHandle);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint sessionHandle, uint fileCount, string[] fileNames,
        uint appCount, RM_UNIQUE_PROCESS[]? apps, uint serviceCount, string[]? serviceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(uint sessionHandle, out uint procInfoNeeded, ref uint procInfo,
        [In, Out] RM_PROCESS_INFO[]? affectedApps, ref uint rebootReasons);

    /// <summary>Returns the ids of processes that currently have the file open (best effort).</summary>
    public static List<int> GetLockingProcessIds(string path)
    {
        var result = new List<int>();
        try
        {
            var key = new StringBuilder(33);
            if (RmStartSession(out var session, 0, key) != 0) return result;
            try
            {
                var files = new[] { path };
                if (RmRegisterResources(session, (uint)files.Length, files, 0, null, 0, null) != 0) return result;

                uint needed = 0, count = 0, reasons = 0;
                var rc = RmGetList(session, out needed, ref count, null, ref reasons);
                if (rc == ERROR_MORE_DATA && needed > 0)
                {
                    var infos = new RM_PROCESS_INFO[needed];
                    count = needed;
                    rc = RmGetList(session, out needed, ref count, infos, ref reasons);
                    if (rc == 0)
                    {
                        for (var i = 0; i < count; i++)
                            result.Add(infos[i].Process.dwProcessId);
                    }
                }
            }
            finally
            {
                RmEndSession(session);
            }
        }
        catch
        {
            // Restart Manager is best effort only.
        }
        return result;
    }
}
