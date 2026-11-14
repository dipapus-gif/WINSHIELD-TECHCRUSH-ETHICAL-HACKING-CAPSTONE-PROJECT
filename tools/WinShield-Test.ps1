<#
  WinShield safe test helper.
  Creates dummy files, simulates ransomware-style behaviour ONLY inside one throwaway folder, then cleans up.

  Usage (PowerShell):
    powershell -ExecutionPolicy Bypass -File .\WinShield-Test.ps1 Setup
    powershell -ExecutionPolicy Bypass -File .\WinShield-Test.ps1 Attack
    powershell -ExecutionPolicy Bypass -File .\WinShield-Test.ps1 Cleanup
#>
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('Setup', 'Attack', 'Cleanup')]
    [string]$Step
)

$ErrorActionPreference = 'Stop'
$Target = Join-Path $env:USERPROFILE 'Documents\WinShield-Test'

switch ($Step) {

    'Setup' {
        New-Item -ItemType Directory -Force -Path $Target | Out-Null
        1..80 | ForEach-Object {
            Set-Content -Path (Join-Path $Target "doc$_.txt") -Value ("Test document $_ " * 200)
        }
        Write-Host "Created 80 dummy files in $Target" -ForegroundColor Green
        Write-Host "Next: in WinShield add this folder, place decoys, build a baseline, create a recovery point, turn protection ON."
    }

    'Attack' {
        if (-not (Test-Path $Target)) { throw "Run 'Setup' first." }
        Write-Host "Simulating an attack inside $Target only ..." -ForegroundColor Yellow

        # 1) touch a decoy file, if WinShield has placed one
        foreach ($d in '!0_Tax_Records_2025.docx', '!0_Account_Passwords_Backup.xlsx', 'zzz_Private_Photos_Archive.pdf') {
            $p = Join-Path $Target $d
            if (Test-Path $p) { Add-Content -Path $p -Value 'tampered'; Write-Host "Touched decoy: $d"; break }
        }

        # 2) overwrite 40 files with random data and rename them to .locked
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        $victims = Get-ChildItem -Path $Target -Filter 'doc*.txt' | Select-Object -First 40
        foreach ($f in $victims) {
            $bytes = New-Object byte[] 20000
            $rng.GetBytes($bytes)
            [IO.File]::WriteAllBytes($f.FullName, $bytes)
            Rename-Item -Path $f.FullName -NewName ($f.Name + '.locked')
            Start-Sleep -Milliseconds 40
        }

        # 3) drop a ransom note
        Set-Content -Path (Join-Path $Target 'HOW_TO_DECRYPT_YOUR_FILES.txt') -Value 'This is only a WinShield test note.'
        Write-Host "Done. Now look at WinShield: Dashboard and Incidents." -ForegroundColor Green
    }

    'Cleanup' {
        if (Test-Path $Target) { Remove-Item -Path $Target -Recurse -Force; Write-Host "Removed $Target" -ForegroundColor Green }
        else { Write-Host 'Nothing to clean up.' }
    }
}
