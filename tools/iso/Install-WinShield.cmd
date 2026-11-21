@echo off
rem Run this from the WinShield ISO (inside your VM or Windows Sandbox).
rem Copies WinShield and the safe test script to C:\WinShield, then starts WinShield.
set "SRC=%~dp0"
if not exist C:\WinShield mkdir C:\WinShield
copy /y "%SRC%WinShield.exe" C:\WinShield\ >nul
copy /y "%SRC%WinShield-Test.ps1" C:\WinShield\ >nul
echo WinShield copied to C:\WinShield
start "" C:\WinShield\WinShield.exe
echo.
echo Next, open PowerShell as administrator in this VM and run:
echo   powershell -ExecutionPolicy Bypass -File C:\WinShield\WinShield-Test.ps1 Setup
echo then add the Documents\WinShield-Test folder in WinShield, turn protection ON, and run the same script with: Attack
pause
