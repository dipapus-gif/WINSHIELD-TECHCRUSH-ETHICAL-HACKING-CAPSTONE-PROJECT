# WinShield Lab

Builds a throwaway Windows virtual machine from a Windows ISO so you can test WinShield (and the ransomware
simulation in `../WinShield-Test.ps1`) without any risk to your real computer.

## What you need
- A Windows 10/11 **Pro, Enterprise or Education** PC (for Hyper-V), or VirtualBox installed on any edition.
- A Windows ISO. Free 90-day evaluation ISOs: <https://www.microsoft.com/evalcenter/>
- About 8 GB free RAM and 70 GB free disk, and virtualization switched on in BIOS/UEFI.

## Steps
1. Double-click **Start-Lab.bat** (accept the administrator prompt).
2. Option **1**: checks your PC and tells you if Hyper-V must be enabled.
3. Option **2**: drag in your Windows ISO. A VM is created and started; install Windows in its window.
4. When Windows is installed and signed in: option **3** saves the **Clean-Install** snapshot.
5. Option **4**: copies WinShield and the test script into the VM (`C:\WinShieldLab`).
6. In the VM follow the printed commands: run WinShield as administrator, then the test script (Setup, then Attack).
7. Option **5** cuts the VM off the network before risky tests (network isolation, process suspension).
8. Option **7** resets the VM to the clean snapshot. Repeat as many times as you like.

Command-line form: `.\WinShield-Lab.ps1 -Action Create -IsoPath "C:\ISOs\Win11.iso"`
(Actions: Check, Create, Stage, Snapshot, Reset, Start, Stop, Isolate, Reconnect, Remove.)

## Notes
- Hyper-V "Stage" uses the Guest Service Interface (on by default in Windows guests). VirtualBox uses a shared folder and needs Guest Additions.
- Nothing here downloads or ships Windows: you provide the ISO and accept Microsoft's licence.
