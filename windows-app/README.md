# WinShield: Windows anti-ransomware detection, prevention and incident response

A WPF (.NET 8) desktop app that watches protected folders for ransomware behaviour, raises alerts with severity levels, takes defensive action (with your confirmation by default) and helps you recover. Everything is stored locally in SQLite.

## Build and run

Requires Windows 10/11 and the .NET 8 SDK.

```powershell
dotnet run
```

Run it as administrator for the full feature set. Without admin rights, monitoring, decoys, integrity checks, backups and alerts all work, but suspending some processes, Controlled Folder Access and network isolation need elevation. The app offers a **Restart as administrator** button.

## Tests

The detection, integrity, backup/restore, report and safety logic is covered by a console test project that compiles the real source files and runs on Windows, Linux or macOS:

```powershell
cd tests\WinShield.Verify
dotnet run
```

It exits 0 when all checks pass. The WPF screens themselves are not covered by automated tests.

## How the spec maps to the code

| Requirement | Where |
|---|---|
| Real-time file monitoring, activity log | `Services/FileActivityMonitor.cs`, `file_events` table |
| Detection: mass modification, renames, extension changes, entropy | `Services/DetectionEngine.cs`, `Services/EntropyCalculator.cs` |
| Rules plus optional machine learning | `Services/DetectionEngine.cs`, `Services/ThreatClassifier.cs`, `tools/train_model.py` |
| Severity levels | `Models/Protection.cs` (`Severity`), `Converters.cs` |
| Honeypot / decoy files, responsible process recorded | `Services/HoneypotService.cs` |
| File integrity (SHA-256 baseline, comparison report) | `Core/IntegrityScanner.cs`, `Services/IntegrityService.cs` |
| Suspicious process, CPU/disk behaviour | `Services/ProcessBehaviorMonitor.cs`, `Services/CommandLineMonitor.cs` |
| Security-service tampering, backup deletion, persistence | `Services/SecurityServiceWatcher.cs`, `Services/CommandLineMonitor.cs`, `Services/PersistenceMonitor.cs` |
| Suspend / terminate processes, with guard rails | `Services/ProcessController.cs`, `Services/ProcessSafety.cs` |
| Restrict apps from protected folders | `Services/ControlledFolderAccessService.cs` (Windows Defender Controlled Folder Access) |
| Emergency protection, confirmation before disruptive actions | `Services/ResponseOrchestrator.cs` |
| Quarantine, network isolation, evidence, recommendations | `QuarantineService`, `NetworkIsolationService`, `EvidenceService`, `RecommendationEngine` |
| Recovery points, verified restore, tamper detection | `Core/BackupStore.cs`, `Services/RecoveryService.cs` |
| Dashboard, incidents, settings | `MainWindow.xaml`, `ViewModels/` |
| HTML and CSV reports | `Core/ReportBuilder.cs`, `Services/ReportService.cs` |
| System health score (10 registry checks) | `Services/SecurityChecks.cs`, `Services/ScanEngine.cs` |

## Safety behaviour

- WinShield never acts on core Windows processes, on itself, or on programs you have marked as trusted.
- Suspending a process, enabling emergency protection and isolating the network ask first unless you turn on the matching automatic option in Settings.
- Quarantined files and damaged versions replaced during a restore are kept, not deleted.
- Detection is heuristic. Expect occasional false alarms (for example during large builds or archive extraction) and mark those incidents as false positives.
- WinShield is a learning and defence-in-depth project. It does not replace Microsoft Defender or a tested off-site backup.

## Data locations

Everything lives under `%LocalAppData%\WinShield`: `winshield.db`, `settings.json`, `model.json` (optional), `Quarantine\`, `Evidence\` and `Backups\`. Reports (HTML or CSV) are saved wherever you choose with the **Save report** buttons on the Incidents tab. The schema is `Data/schema.sql`.

## Optional machine-learning model

```powershell
python tools\train_model.py            # synthetic demo data, writes model.json
python tools\train_model.py --csv windows.csv
```

Copy the resulting `model.json` into `%LocalAppData%\WinShield`. Without it the classifier is off and the rule engine works alone. The model can add an alert but can never cancel one raised by a rule or a decoy file. The default model is trained on synthetic data, so treat it as a demonstration.

## Scan-history report script

```powershell
python tools\report.py --out report.md
```
