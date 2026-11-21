WinShield sandbox ISO
=====================
Contents: WinShield.exe (self-contained, no .NET install needed), WinShield-Test.ps1 (safe ransomware
simulation), Install-WinShield.cmd, WinShield-Sandbox.wsb.

Use in a VM / sandbox:
 1. Attach this ISO to your VM as a DVD drive (Hyper-V: Settings > DVD Drive; VirtualBox: Storage > add disc).
 2. Inside the VM open the DVD and double-click Install-WinShield.cmd.
 3. Create an account in WinShield, then follow the on-screen test steps.
Windows Sandbox: copy WinShield.exe and WinShield-Test.ps1 to C:\WinShieldSandbox on your PC, then
double-click WinShield-Sandbox.wsb. Run the test only inside the VM/sandbox, never on your real PC.
