using Microsoft.Win32;
using WinShield.Models;

namespace WinShield.Services;

/// <summary>
/// Read-only checks of common Windows security settings. Every check only reads
/// the registry; nothing on the machine is changed.
/// </summary>
internal static class SecurityChecks
{
    private static RegistryKey? OpenHklm(string path)
    {
        using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        return baseKey.OpenSubKey(path);
    }

    private static object? ReadHklm(string path, string name)
    {
        using var key = OpenHklm(path);
        return key?.GetValue(name);
    }

    private static int? ReadHklmInt(string path, string name)
    {
        var value = ReadHklm(path, name);
        return value is int i ? i : null;
    }

    public static CheckResult Defender()
    {
        const string id = "defender_realtime";
        const string title = "Microsoft Defender real-time protection";

        // Group Policy can switch real-time protection off without touching the user setting.
        var policyOff = ReadHklmInt(@"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring");
        var userOff = ReadHklmInt(@"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring");
        var antiSpywareOff = ReadHklmInt(@"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware");

        if (policyOff == 1 || userOff == 1 || antiSpywareOff == 1)
        {
            return new CheckResult(id, title, CheckStatus.Fail,
                "Real-time protection is turned off.",
                "Open Windows Security > Virus & threat protection and turn Real-time protection on. If a third-party antivirus is installed, confirm it is active.");
        }

        return new CheckResult(id, title, CheckStatus.Pass,
            "Real-time protection is not disabled by policy or settings.",
            "No action needed.");
    }

    public static CheckResult Firewall()
    {
        const string id = "firewall_profiles";
        const string title = "Windows Firewall profiles";
        const string basePath = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";

        var profiles = new (string Label, string Key)[]
        {
            ("Domain", "DomainProfile"),
            ("Private", "StandardProfile"),
            ("Public", "PublicProfile")
        };

        var disabled = new List<string>();
        foreach (var (label, key) in profiles)
        {
            var enabled = ReadHklmInt($@"{basePath}\{key}", "EnableFirewall");
            if (enabled == 0) disabled.Add(label);
        }

        if (disabled.Count == 0)
        {
            return new CheckResult(id, title, CheckStatus.Pass,
                "Domain, Private and Public firewall profiles are all enabled.",
                "No action needed.");
        }

        return new CheckResult(id, title, CheckStatus.Fail,
            $"Firewall is disabled on: {string.Join(", ", disabled)}.",
            "Open Windows Security > Firewall & network protection and turn the firewall on for every profile.");
    }

    public static CheckResult Uac()
    {
        const string id = "uac_enabled";
        const string title = "User Account Control (UAC)";

        var enableLua = ReadHklmInt(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA");
        if (enableLua == 0)
        {
            return new CheckResult(id, title, CheckStatus.Fail,
                "UAC is disabled, so programs can run with administrator rights without a prompt.",
                "Open Change User Account Control settings and move the slider up from 'Never notify', then restart.");
        }

        var consent = ReadHklmInt(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin");
        if (consent == 0)
        {
            return new CheckResult(id, title, CheckStatus.Warning,
                "UAC is on but administrators are elevated without a prompt.",
                "Set the UAC level to at least 'Notify me only when apps try to make changes'.");
        }

        return new CheckResult(id, title, CheckStatus.Pass,
            "UAC is enabled and prompts for elevation.",
            "No action needed.");
    }

    public static CheckResult WindowsUpdate()
    {
        const string id = "windows_update";
        const string title = "Windows Update service";

        var start = ReadHklmInt(@"SYSTEM\CurrentControlSet\Services\wuauserv", "Start");
        var noAutoUpdate = ReadHklmInt(@"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate");

        if (start == 4)
        {
            return new CheckResult(id, title, CheckStatus.Fail,
                "The Windows Update service is disabled.",
                "Set the 'Windows Update' service startup type to Manual or Automatic so security patches can install.");
        }

        if (noAutoUpdate == 1)
        {
            return new CheckResult(id, title, CheckStatus.Warning,
                "Automatic updates are turned off by policy.",
                "Make sure updates are installed some other way (for example WSUS or Intune), or re-enable automatic updates.");
        }

        return new CheckResult(id, title, CheckStatus.Pass,
            "The Windows Update service is available and automatic updates are not blocked.",
            "No action needed.");
    }

    public static CheckResult SmartScreen()
    {
        const string id = "smartscreen";
        const string title = "SmartScreen app reputation checks";

        var value = ReadHklm(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled") as string;
        if (string.Equals(value, "Off", StringComparison.OrdinalIgnoreCase))
        {
            return new CheckResult(id, title, CheckStatus.Fail,
                "SmartScreen is turned off.",
                "Open Windows Security > App & browser control > Reputation-based protection and turn it on.");
        }

        return new CheckResult(id, title, CheckStatus.Pass,
            string.IsNullOrEmpty(value) ? "SmartScreen is at its default setting." : $"SmartScreen is set to '{value}'.",
            "No action needed.");
    }

    public static CheckResult RemoteDesktop()
    {
        const string id = "remote_desktop";
        const string title = "Remote Desktop";

        var deny = ReadHklmInt(@"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");
        if (deny == 0)
        {
            var nla = ReadHklmInt(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");
            return nla == 1
                ? new CheckResult(id, title, CheckStatus.Warning,
                    "Remote Desktop is enabled and requires Network Level Authentication.",
                    "If you do not need remote access to this PC, turn Remote Desktop off in Settings > System > Remote Desktop.")
                : new CheckResult(id, title, CheckStatus.Fail,
                    "Remote Desktop is enabled without Network Level Authentication.",
                    "Turn Remote Desktop off, or require Network Level Authentication in the Remote Desktop settings.");
        }

        return new CheckResult(id, title, CheckStatus.Pass,
            "Remote Desktop connections are not allowed.",
            "No action needed.");
    }

    public static CheckResult Smb1()
    {
        const string id = "smb1";
        const string title = "SMBv1 file sharing protocol";

        var smb1 = ReadHklmInt(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
        if (smb1 == 1)
        {
            return new CheckResult(id, title, CheckStatus.Fail,
                "The legacy SMBv1 protocol is enabled.",
                "Turn off 'SMB 1.0/CIFS File Sharing Support' in Windows Features. SMBv1 has known serious vulnerabilities.");
        }

        return new CheckResult(id, title, CheckStatus.Pass,
            "SMBv1 is not explicitly enabled.",
            "No action needed.");
    }

    public static CheckResult AutoLogon()
    {
        const string id = "autologon";
        const string title = "Automatic sign-in";

        var auto = ReadHklm(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon") as string;
        if (auto == "1")
        {
            return new CheckResult(id, title, CheckStatus.Warning,
                "Windows signs in automatically without asking for a password.",
                "Turn off automatic sign-in, especially on laptops or shared machines.");
        }

        return new CheckResult(id, title, CheckStatus.Pass,
            "Automatic sign-in is not configured.",
            "No action needed.");
    }

    public static CheckResult SecureBoot()
    {
        const string id = "secure_boot";
        const string title = "Secure Boot";

        var state = ReadHklmInt(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled");
        return state switch
        {
            1 => new CheckResult(id, title, CheckStatus.Pass,
                "Secure Boot is enabled.", "No action needed."),
            0 => new CheckResult(id, title, CheckStatus.Warning,
                "Secure Boot is supported but turned off.",
                "Turn on Secure Boot in your PC's UEFI/BIOS settings."),
            _ => new CheckResult(id, title, CheckStatus.Info,
                "Secure Boot state could not be read (legacy BIOS, or not supported).",
                "No action needed unless your PC should be using UEFI.")
        };
    }

    public static CheckResult StartupItems()
    {
        const string id = "startup_items";
        const string title = "Programs that start with Windows";

        var count = 0;
        var names = new List<string>();

        void Collect(RegistryHive hive, string path)
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(path);
            if (key is null) return;
            foreach (var name in key.GetValueNames())
            {
                count++;
                if (names.Count < 8) names.Add(name);
            }
        }

        const string run = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        Collect(RegistryHive.LocalMachine, run);
        Collect(RegistryHive.CurrentUser, run);

        var detail = count == 0
            ? "No programs found in the Run registry keys."
            : $"{count} program(s) start with Windows, for example: {string.Join(", ", names)}.";

        return new CheckResult(id, title, count > 25 ? CheckStatus.Warning : CheckStatus.Info, detail,
            "Review startup programs in Task Manager > Startup apps and disable any you do not recognise.");
    }
}
