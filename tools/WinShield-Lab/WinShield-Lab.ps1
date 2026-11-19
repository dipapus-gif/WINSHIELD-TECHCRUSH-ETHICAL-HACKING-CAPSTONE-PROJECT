<#
.SYNOPSIS
  WinShield Lab: build and manage a throwaway Windows test VM from a Windows ISO.

.DESCRIPTION
  Works with Hyper-V (Windows 10/11 Pro, Enterprise, Education) or VirtualBox.
  Typical flow:  Check -> Create -> (install Windows in the VM) -> Snapshot -> Stage -> test -> Reset

  Run with no arguments for an interactive menu, or use -Action directly.
  You supply the Windows ISO. Free 90-day evaluation ISOs: https://www.microsoft.com/evalcenter/
#>
[CmdletBinding()]
param(
    [ValidateSet('Menu', 'Check', 'Create', 'Stage', 'Snapshot', 'Reset', 'Start', 'Stop', 'Isolate', 'Reconnect', 'Remove')]
    [string]$Action = 'Menu',

    [string]$IsoPath,
    [string]$Name = 'WinShield-Lab',
    [int]$MemoryGB = 4,
    [int]$CpuCount = 2,
    [int]$DiskGB = 64,
    [ValidateSet('Auto', 'HyperV', 'VirtualBox')]
    [string]$Backend = 'Auto',
    [string]$SnapshotName = 'Clean-Install',
    [string]$ReleaseZipUrl = 'https://github.com/dipapus-gif/WINSHIELD-TECHCRUSH-ETHICAL-HACKING-CAPSTONE-PROJECT/releases/latest/download/WinShield-win-x64.zip',
    [string]$TestScriptUrl = 'https://raw.githubusercontent.com/dipapus-gif/WINSHIELD-TECHCRUSH-ETHICAL-HACKING-CAPSTONE-PROJECT/main/tools/WinShield-Test.ps1'
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ------------------------------------------------------------------ helpers

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# VM tools need administrator rights: relaunch elevated with the same arguments.
if (-not (Test-Admin)) {
    Write-Host 'Administrator rights are needed. Asking Windows to elevate...' -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    foreach ($k in $PSBoundParameters.Keys) { $argList += "-$k"; $argList += "`"$($PSBoundParameters[$k])`"" }
    Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $argList
    exit
}

function Write-Step([string]$text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Write-Ok([string]$text)   { Write-Host "   $text" -ForegroundColor Green }
function Write-Warn([string]$text) { Write-Host "   $text" -ForegroundColor Yellow }

function Get-VBoxManage {
    $candidates = @(
        (Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'Oracle\VirtualBox\VBoxManage.exe')
    )
    foreach ($c in $candidates) { if ($c -and (Test-Path $c)) { return $c } }
    return $null
}

function Test-HyperVReady {
    if (-not (Get-Command Get-VM -ErrorAction SilentlyContinue)) { return $false }
    try { $null = Get-VMHost; return $true } catch { return $false }
}

function Resolve-Backend {
    if ($Backend -ne 'Auto') { return $Backend }
    if (Test-HyperVReady) { return 'HyperV' }
    if (Get-VBoxManage)   { return 'VirtualBox' }
    throw 'Neither Hyper-V nor VirtualBox is available. Run the Check action for what to install.'
}

function Assert-Iso {
    if (-not $IsoPath) { throw 'Give the Windows ISO with -IsoPath "C:\path\Windows.iso".' }
    $IsoPath = $IsoPath.Trim('"')
    if (-not (Test-Path -LiteralPath $IsoPath)) { throw "ISO not found: $IsoPath" }
    Set-Variable -Name IsoPath -Value $IsoPath -Scope Script
}

# ------------------------------------------------------------------ Check

function Invoke-Check {
    Write-Step 'Checking this computer'
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    Write-Ok "Windows: $($os.Caption)"
    Write-Ok ("RAM: {0:N1} GB   (the VM will use {1} GB)" -f ($cs.TotalPhysicalMemory / 1GB), $MemoryGB)
    $drive = (Get-Item $env:USERPROFILE).PSDrive
    Write-Ok ("Free disk on {0}: {1:N0} GB   (the VM can grow to {2} GB)" -f $drive.Name, ($drive.Free / 1GB), $DiskGB)

    if ($cs.TotalPhysicalMemory / 1GB -lt ($MemoryGB + 4)) { Write-Warn 'Low RAM: try -MemoryGB 3 or close other programs.' }

    Write-Host ''
    if (Test-HyperVReady) {
        Write-Ok 'Hyper-V: ready (recommended)'
    } else {
        $feature = $null
        try { $feature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction Stop } catch { }
        if ($feature -and $feature.State -eq 'Enabled') {
            Write-Warn 'Hyper-V is enabled but not responding. Restart the computer and try again.'
        } else {
            Write-Warn 'Hyper-V is not enabled (it needs Windows Pro/Enterprise/Education). To enable it, run this and restart:'
            Write-Host '     Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -All' -ForegroundColor Gray
        }
    }
    if (Get-VBoxManage) { Write-Ok 'VirtualBox: found' } else { Write-Warn 'VirtualBox: not installed (optional alternative: virtualbox.org)' }

    if (-not $cs.HypervisorPresent -and -not (Get-VBoxManage)) {
        Write-Warn 'Also check that virtualization (Intel VT-x / AMD-V) is switched on in the BIOS/UEFI.'
    }
}

# ------------------------------------------------------------------ Hyper-V

function Get-HvSwitchName {
    $s = Get-VMSwitch -Name 'Default Switch' -ErrorAction SilentlyContinue
    if ($s) { return $s.Name }
    $s = Get-VMSwitch -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($s) { return $s.Name }
    return $null
}

function New-HvLab {
    Assert-Iso
    if (Get-VM -Name $Name -ErrorAction SilentlyContinue) { throw "A VM named '$Name' already exists. Use -Name for another, or Remove it first." }

    Write-Step "Creating Hyper-V VM '$Name'"
    $dir = Join-Path (Get-VMHost).VirtualMachinePath $Name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $vhd = Join-Path $dir "$Name.vhdx"

    $params = @{
        Name               = $Name
        Generation         = 2
        MemoryStartupBytes = [int64]$MemoryGB * 1GB
        NewVHDPath         = $vhd
        NewVHDSizeBytes    = [int64]$DiskGB * 1GB
    }
    $switch = Get-HvSwitchName
    if ($switch) { $params.SwitchName = $switch } else { Write-Warn 'No virtual switch found: the VM starts without a network.' }
    $null = New-VM @params

    Set-VM -Name $Name -ProcessorCount $CpuCount -AutomaticCheckpointsEnabled $false -CheckpointType Standard
    Set-VMMemory -VMName $Name -DynamicMemoryEnabled $false
    Set-VMFirmware -VMName $Name -EnableSecureBoot On -SecureBootTemplate 'MicrosoftWindows'
    # Windows 11 wants a TPM; harmless for Windows 10.
    Set-VMKeyProtector -VMName $Name -NewLocalKeyProtector
    Enable-VMTPM -VMName $Name
    Enable-VMIntegrationService -VMName $Name -Name 'Guest Service Interface'

    $null = Add-VMDvdDrive -VMName $Name -Path $IsoPath
    $dvd = Get-VMDvdDrive -VMName $Name
    Set-VMFirmware -VMName $Name -FirstBootDevice $dvd

    Start-VM -Name $Name
    Write-Ok "VM started. Opening its window: install Windows (press any key at 'Press any key to boot from CD')."
    Start-Process -FilePath 'vmconnect.exe' -ArgumentList 'localhost', $Name
    Show-NextAfterCreate
}

function Invoke-HvStage {
    $vm = Get-VM -Name $Name
    if ($vm.State -ne 'Running') { throw "VM '$Name' is not running. Start it and sign in to Windows first." }
    Enable-VMIntegrationService -VMName $Name -Name 'Guest Service Interface'

    $tmp = Join-Path $env:TEMP 'winshield-lab'
    New-Item -ItemType Directory -Force -Path $tmp | Out-Null
    $zip = Join-Path $tmp 'WinShield-win-x64.zip'
    $ps1 = Join-Path $tmp 'WinShield-Test.ps1'

    Write-Step 'Downloading WinShield and the test script'
    Invoke-WebRequest -Uri $ReleaseZipUrl -OutFile $zip -UseBasicParsing
    Invoke-WebRequest -Uri $TestScriptUrl -OutFile $ps1 -UseBasicParsing
    Write-Ok ("WinShield zip: {0:N0} MB" -f ((Get-Item $zip).Length / 1MB))

    Write-Step "Copying into the VM (C:\WinShieldLab)"
    Copy-VMFile -Name $Name -SourcePath $zip -DestinationPath 'C:\WinShieldLab\WinShield-win-x64.zip' -CreateFullPath -FileSource Host -Force
    Copy-VMFile -Name $Name -SourcePath $ps1 -DestinationPath 'C:\WinShieldLab\WinShield-Test.ps1' -CreateFullPath -FileSource Host -Force
    Show-NextAfterStage
}

function Get-HvCleanSnapshot {
    Get-VMSnapshot -VMName $Name -Name $SnapshotName -ErrorAction SilentlyContinue
}

# ------------------------------------------------------------------ VirtualBox

function Invoke-VBox { param([string[]]$VBoxArgs) & $script:VBox @VBoxArgs; if ($LASTEXITCODE -ne 0) { throw "VBoxManage failed: $($VBoxArgs -join ' ')" } }

function New-VBoxLab {
    Assert-Iso
    $script:VBox = Get-VBoxManage
    Write-Step "Creating VirtualBox VM '$Name'"
    $dir = Join-Path $env:USERPROFILE "VirtualBox VMs\$Name"
    $vdi = Join-Path $dir "$Name.vdi"

    Invoke-VBox @('createvm', '--name', $Name, '--ostype', 'Windows11_64', '--register')
    Invoke-VBox @('modifyvm', $Name, '--memory', ($MemoryGB * 1024), '--cpus', $CpuCount, '--firmware', 'efi',
        '--tpm-type', '2.0', '--nic1', 'nat', '--graphicscontroller', 'vboxsvga', '--vram', '128',
        '--boot1', 'dvd', '--boot2', 'disk')
    Invoke-VBox @('createmedium', 'disk', '--filename', $vdi, '--size', ($DiskGB * 1024), '--format', 'VDI')
    Invoke-VBox @('storagectl', $Name, '--name', 'SATA', '--add', 'sata', '--controller', 'IntelAhci')
    Invoke-VBox @('storageattach', $Name, '--storagectl', 'SATA', '--port', '0', '--device', '0', '--type', 'hdd', '--medium', $vdi)
    Invoke-VBox @('storageattach', $Name, '--storagectl', 'SATA', '--port', '1', '--device', '0', '--type', 'dvddrive', '--medium', $IsoPath)
    Invoke-VBox @('startvm', $Name, '--type', 'gui')
    Write-Ok 'VM started. Install Windows in the VM window.'
    Show-NextAfterCreate
}

function Invoke-VBoxStage {
    $script:VBox = Get-VBoxManage
    $share = Join-Path $env:USERPROFILE 'WinShield-Lab-Share'
    New-Item -ItemType Directory -Force -Path $share | Out-Null
    Write-Step 'Downloading WinShield and the test script'
    Invoke-WebRequest -Uri $ReleaseZipUrl -OutFile (Join-Path $share 'WinShield-win-x64.zip') -UseBasicParsing
    Invoke-WebRequest -Uri $TestScriptUrl -OutFile (Join-Path $share 'WinShield-Test.ps1') -UseBasicParsing
    & $script:VBox sharedfolder remove $Name --name WinShieldShare 2>$null | Out-Null
    Invoke-VBox @('sharedfolder', 'add', $Name, '--name', 'WinShieldShare', '--hostpath', $share, '--automount')
    Write-Ok "Shared folder ready: $share"
    Write-Warn 'In the VM: Devices menu > Insert Guest Additions CD image, install it, restart the VM; the files then appear as a network drive in File Explorer.'
}

# ------------------------------------------------------------------ messages

function Show-NextAfterCreate {
    Write-Host @"

NEXT
  1. Finish installing Windows inside the VM and sign in.
  2. When Windows is fresh and tidy, take the clean snapshot:
       .\WinShield-Lab.ps1 -Action Snapshot
  3. Copy WinShield and the test script into the VM:
       .\WinShield-Lab.ps1 -Action Stage
"@ -ForegroundColor Gray
}

function Show-NextAfterStage {
    Write-Host @"

INSIDE THE VM (open PowerShell as administrator)
  Expand-Archive C:\WinShieldLab\WinShield-win-x64.zip C:\WinShieldLab\WinShield -Force
  C:\WinShieldLab\WinShield\WinShield.exe          # create an account, add the test folder, turn protection on
  powershell -ExecutionPolicy Bypass -File C:\WinShieldLab\WinShield-Test.ps1 Setup
  ... add the folder in WinShield, place decoys, baseline, recovery point, protection ON ...
  powershell -ExecutionPolicy Bypass -File C:\WinShieldLab\WinShield-Test.ps1 Attack

BACK ON THIS COMPUTER
  Cut the VM off the network before risky tests:  .\WinShield-Lab.ps1 -Action Isolate
  Undo everything after a test:                   .\WinShield-Lab.ps1 -Action Reset
"@ -ForegroundColor Gray
}

# ------------------------------------------------------------------ actions

function Invoke-LabAction([string]$what) {
    $be = Resolve-Backend
    switch ($what) {
        'Check'  { Invoke-Check }

        'Create' { if ($be -eq 'HyperV') { New-HvLab } else { New-VBoxLab } }

        'Stage'  { if ($be -eq 'HyperV') { Invoke-HvStage } else { Invoke-VBoxStage } }

        'Start' {
            if ($be -eq 'HyperV') { Start-VM -Name $Name; Start-Process vmconnect.exe -ArgumentList 'localhost', $Name }
            else { Invoke-VBox @('startvm', $Name, '--type', 'gui') }
            Write-Ok 'Started.'
        }

        'Stop' {
            if ($be -eq 'HyperV') { Stop-VM -Name $Name -TurnOff -Force } else { Invoke-VBox @('controlvm', $Name, 'poweroff') }
            Write-Ok 'Stopped.'
        }

        'Snapshot' {
            Write-Step "Saving snapshot '$SnapshotName'"
            if ($be -eq 'HyperV') {
                if (Get-HvCleanSnapshot) { Remove-VMSnapshot -VMName $Name -Name $SnapshotName }
                Checkpoint-VM -Name $Name -SnapshotName $SnapshotName
            } else {
                $script:VBox = Get-VBoxManage
                & $script:VBox snapshot $Name delete $SnapshotName 2>$null | Out-Null
                Invoke-VBox @('snapshot', $Name, 'take', $SnapshotName)
            }
            Write-Ok 'Saved. "Reset" returns the VM to exactly this state.'
        }

        'Reset' {
            Write-Step "Restoring snapshot '$SnapshotName'"
            if ($be -eq 'HyperV') {
                if (-not (Get-HvCleanSnapshot)) { throw "No snapshot named '$SnapshotName'. Take one first (Action Snapshot)." }
                Stop-VM -Name $Name -TurnOff -Force -ErrorAction SilentlyContinue
                Restore-VMSnapshot -VMName $Name -Name $SnapshotName -Confirm:$false
                Start-VM -Name $Name
                Start-Process vmconnect.exe -ArgumentList 'localhost', $Name
            } else {
                $script:VBox = Get-VBoxManage
                & $script:VBox controlvm $Name poweroff 2>$null | Out-Null
                Start-Sleep -Seconds 3
                Invoke-VBox @('snapshot', $Name, 'restore', $SnapshotName)
                Invoke-VBox @('startvm', $Name, '--type', 'gui')
            }
            Write-Ok 'VM is back to the clean state.'
        }

        'Isolate' {
            if ($be -eq 'HyperV') { Get-VMNetworkAdapter -VMName $Name | Disconnect-VMNetworkAdapter }
            else { Invoke-VBox @('controlvm', $Name, 'setlinkstate1', 'off') }
            Write-Ok 'Network cable pulled: the VM cannot reach the internet or your other computers.'
        }

        'Reconnect' {
            if ($be -eq 'HyperV') {
                $sw = Get-HvSwitchName
                if (-not $sw) { throw 'No virtual switch to reconnect to.' }
                Get-VMNetworkAdapter -VMName $Name | Connect-VMNetworkAdapter -SwitchName $sw
            } else { Invoke-VBox @('controlvm', $Name, 'setlinkstate1', 'on') }
            Write-Ok 'Network reconnected.'
        }

        'Remove' {
            $ok = Read-Host "Delete VM '$Name' and its disk? Type YES to confirm"
            if ($ok -ne 'YES') { Write-Warn 'Cancelled.'; return }
            if ($be -eq 'HyperV') {
                $vm = Get-VM -Name $Name
                $paths = $vm.HardDrives.Path
                Stop-VM -Name $Name -TurnOff -Force -ErrorAction SilentlyContinue
                Remove-VMSnapshot -VMName $Name -ErrorAction SilentlyContinue
                Remove-VM -Name $Name -Force
                foreach ($p in $paths) { if ($p -and (Test-Path $p)) { Remove-Item -LiteralPath $p -Force } }
            } else {
                $script:VBox = Get-VBoxManage
                Invoke-VBox @('unregistervm', $Name, '--delete')
            }
            Write-Ok 'Removed.'
        }
    }
}

function Show-Menu {
    while ($true) {
        Write-Host ''
        Write-Host '  WinShield Lab: safe Windows test VM' -ForegroundColor Cyan
        Write-Host '  1  Check this computer'
        Write-Host '  2  Create the VM from a Windows ISO'
        Write-Host '  3  Save the clean snapshot (after Windows is installed)'
        Write-Host '  4  Copy WinShield + test script into the VM'
        Write-Host '  5  Cut the VM off the network'
        Write-Host '  6  Reconnect the network'
        Write-Host '  7  Reset the VM to the clean snapshot'
        Write-Host '  8  Start    9  Stop    R  Remove the VM    Q  Quit'
        $c = (Read-Host '  Choose').Trim().ToUpper()
        try {
            switch ($c) {
                '1' { Invoke-LabAction 'Check' }
                '2' {
                    if (-not $IsoPath) { $script:IsoPath = (Read-Host '  Path to the Windows ISO (drag the file here)').Trim('"', ' ') }
                    Invoke-LabAction 'Create'
                }
                '3' { Invoke-LabAction 'Snapshot' }
                '4' { Invoke-LabAction 'Stage' }
                '5' { Invoke-LabAction 'Isolate' }
                '6' { Invoke-LabAction 'Reconnect' }
                '7' { Invoke-LabAction 'Reset' }
                '8' { Invoke-LabAction 'Start' }
                '9' { Invoke-LabAction 'Stop' }
                'R' { Invoke-LabAction 'Remove' }
                'Q' { return }
                default { Write-Warn 'Pick a number from the list.' }
            }
        } catch {
            Write-Host "   Problem: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# ------------------------------------------------------------------ run

try {
    if ($Action -eq 'Menu') { Show-Menu } else { Invoke-LabAction $Action }
} catch {
    Write-Host "Problem: $($_.Exception.Message)" -ForegroundColor Red
    if ($Action -ne 'Menu') { exit 1 }
}
if ($Action -ne 'Menu' -and $Host.Name -eq 'ConsoleHost' -and -not $env:WINSHIELD_LAB_NOPAUSE) { Read-Host 'Press Enter to close' | Out-Null }
