using WinShield.Core;
using WinShield.Services;
using WinShield.Ui;

namespace WinShield.ViewModels;

/// <summary>The settings people actually need to change. Detection thresholds stay in settings.json.</summary>
public sealed class SettingsViewModel : ViewModelBase
{
    private readonly ProtectionService _protection;
    private readonly IUiServices _ui;

    private int _responseModeIndex;
    private bool _autoIsolate;
    private bool _honeypots;
    private string _backupFolder = "";
    private int _maxRecoveryPoints;
    private int _autoPointHours;
    private string _message = "";

    public SettingsViewModel(ProtectionService protection, IUiServices ui)
    {
        _protection = protection;
        _ui = ui;

        SaveCommand = new RelayCommand(SaveAsync);
        BrowseBackupFolderCommand = new RelayCommand(() =>
        {
            var folder = _ui.PickFolder("Choose where recovery points are stored");
            if (!string.IsNullOrWhiteSpace(folder)) BackupFolder = folder;
        });
        OpenDataFolderCommand = new RelayCommand(() => _ui.Open(AppPaths.Root));
    }

    public RelayCommand SaveCommand { get; }
    public RelayCommand BrowseBackupFolderCommand { get; }
    public RelayCommand OpenDataFolderCommand { get; }

    public int ResponseModeIndex
    {
        get => _responseModeIndex;
        set { if (SetField(ref _responseModeIndex, value)) OnPropertyChanged(nameof(ResponseModeHelp)); }
    }

    public string ResponseModeHelp => (ResponseMode)Math.Clamp(ResponseModeIndex, 0, 2) switch
    {
        ResponseMode.MonitorOnly => "Detect and alert only. WinShield never touches processes or the network.",
        ResponseMode.AskFirst => "Detect, then ask you before suspending a process or cutting off the network.",
        _ => "Act automatically on critical threats (and high threats with a known process). Fastest, but may act without you."
    };

    public bool AutoIsolateOnCritical { get => _autoIsolate; set => SetField(ref _autoIsolate, value); }
    public bool HoneypotsEnabled { get => _honeypots; set => SetField(ref _honeypots, value); }
    public string BackupFolder { get => _backupFolder; set => SetField(ref _backupFolder, value); }
    public int MaxRecoveryPoints { get => _maxRecoveryPoints; set => SetField(ref _maxRecoveryPoints, value); }
    public int AutoRecoveryPointHours { get => _autoPointHours; set => SetField(ref _autoPointHours, value); }
    public string Message { get => _message; private set => SetField(ref _message, value); }

    public string ModelStatus => "Machine-learning classifier: " + _protection.Classifier.Description;
    public string DataFolder => AppPaths.Root;

    public void Load()
    {
        var s = _protection.Settings.Current;
        ResponseModeIndex = (int)s.ResponseMode;
        AutoIsolateOnCritical = s.AutoIsolateOnCritical;
        HoneypotsEnabled = s.HoneypotsEnabled;
        BackupFolder = s.BackupFolder;
        MaxRecoveryPoints = s.MaxRecoveryPoints;
        AutoRecoveryPointHours = s.AutoRecoveryPointHours;
        OnPropertyChanged(nameof(ModelStatus));
    }

    private async Task SaveAsync()
    {
        if (AutoIsolateOnCritical && ResponseModeIndex == (int)ResponseMode.MonitorOnly)
        {
            Message = "Automatic network isolation needs a response mode other than 'Monitor only'.";
            return;
        }

        var s = _protection.Settings.Current;
        s.ResponseMode = (ResponseMode)Math.Clamp(ResponseModeIndex, 0, 2);
        s.AutoIsolateOnCritical = AutoIsolateOnCritical;
        s.HoneypotsEnabled = HoneypotsEnabled;
        s.BackupFolder = string.IsNullOrWhiteSpace(BackupFolder) ? AppPaths.DefaultBackups : BackupFolder.Trim();
        s.MaxRecoveryPoints = MaxRecoveryPoints;
        s.AutoRecoveryPointHours = AutoRecoveryPointHours;

        await Task.Run(_protection.Settings.Save);
        Load(); // show the values after the service has clamped them to safe ranges
        Message = "Settings saved.";
    }
}
