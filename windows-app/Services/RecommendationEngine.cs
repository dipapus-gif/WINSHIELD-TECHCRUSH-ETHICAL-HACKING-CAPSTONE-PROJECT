using WinShield.Models;

namespace WinShield.Services;

/// <summary>Plain-language guidance for incident reports and the incident page.</summary>
public static class RecommendationEngine
{
    public static List<string> ForIncident(Incident incident, IReadOnlyCollection<IncidentAction> actions, bool networkIsolated)
    {
        var tips = new List<string>();
        var rules = incident.RuleIds;
        bool Has(string id) => rules.Contains(id, StringComparison.OrdinalIgnoreCase);

        if (incident.Severity >= Severity.High)
        {
            if (!networkIsolated)
                tips.Add("Disconnect this PC from Wi-Fi and network cables now so the threat cannot spread to other devices or shares.");
            tips.Add("Do not restart or shut down until you have copied the evidence folder; running processes and logs help investigators.");
        }

        if (Has("R-HONEYPOT"))
            tips.Add("A decoy file was touched. Treat every file in the protected folders as potentially affected until integrity is verified.");
        if (Has("R-MASS-MODIFY") || Has("R-EXT-CHANGE") || Has("R-ENTROPY") || Has("R-SUSPICIOUS-EXT"))
            tips.Add("Run an Integrity comparison to list exactly which files changed, then restore those from a verified recovery point or offline backup.");
        if (Has("R-RANSOM-NOTE"))
            tips.Add("Keep a copy of the ransom note (do not open links in it). It can identify the ransomware family and whether a free decryptor exists at nomoreransom.org.");
        if (Has("C-SHADOW-DELETE") || Has("C-BACKUP-DELETE"))
            tips.Add("Windows restore points and backups were targeted. Rely on your WinShield recovery points and offline backups, and check they are intact.");
        if (Has("C-DEFENDER-OFF") || Has("S-DEFENDER-RT") || Has("S-DEFENDER-SVC"))
            tips.Add("Turn Microsoft Defender protection back on and run a full scan from Windows Security (use the offline scan if malware is suspected).");
        if (Has("S-FIREWALL") || Has("C-FIREWALL-OFF"))
            tips.Add("Re-enable the Windows Firewall for all profiles in Windows Security.");
        if (Has("P-NEW-PERSISTENCE"))
            tips.Add("Review startup programs and scheduled tasks you do not recognise (Task Manager > Startup apps, Task Scheduler) and remove them.");

        if (incident.ProcessName is not null)
        {
            var handled = actions.Any(a => a.Success && a.Action is "Process suspended" or "Process terminated" or "Image quarantined");
            tips.Add(handled
                ? $"{incident.ProcessName} was contained. Quarantine or delete its program file, then scan the PC before returning to normal use."
                : $"{incident.ProcessName} (PID {incident.ProcessId}) was linked to this activity but not stopped. If you do not recognise it, suspend or terminate it from the incident page.");
        }

        tips.Add("Change passwords for important accounts from a different, clean device, especially if this PC was signed in to email, banking or work systems.");
        tips.Add("If this is a work or school device, report the incident to your IT or security team before reconnecting to the network.");
        return tips;
    }

    public static List<string> General() => new()
    {
        "Keep at least one backup offline or on a separate account (the 3-2-1 rule: 3 copies, 2 media types, 1 off-site). Ransomware encrypts connected drives.",
        "Install Windows and application updates promptly; most ransomware enters through known, already-fixed vulnerabilities.",
        "Do not open attachments or links you did not expect, and block macros in documents from the internet.",
        "Use a standard (non-administrator) account for daily work and keep User Account Control turned on.",
        "Turn on Microsoft Defender real-time protection and Controlled Folder Access for important folders.",
        "Disable Remote Desktop and SMBv1 if you do not need them, and use multi-factor authentication for remote access.",
        "Test restoring from your backups regularly. A backup you have never restored is only a hope."
    };

    public static List<string> RecoveryGuidance() => new()
    {
        "1. Contain first: disconnect from the network, then stop or suspend the suspicious process.",
        "2. Do not pay or contact the attacker. Check nomoreransom.org for a free decryptor for your ransomware family.",
        "3. Remove the cause: quarantine the malicious program, run a full offline Defender scan, and remove unknown startup entries.",
        "4. Only after the PC is clean, restore files from a WinShield recovery point or an offline backup. WinShield verifies every restored file against its recorded SHA-256 hash.",
        "5. Compare against your integrity baseline to confirm no file is still modified, deleted or unexpected.",
        "6. Change passwords from a clean device and review account sign-in activity.",
        "7. Reconnect to the network and keep protection in AskFirst or AutoContain mode for the next few weeks."
    };
}
