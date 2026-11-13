# WinShield: Intelligent Windows Anti-Ransomware Detection, Prevention and Incident Response

TechCrush Ethical Hacking capstone project.

| Folder | What it is |
|---|---|
| `windows-app/` | WPF .NET 8 desktop app with on-device accounts (create account, sign in, forgot password via recovery key). Build with `cd windows-app && dotnet run` (Windows 10/11, .NET 8 SDK). |
| `browser-app/index.html` | Single-file browser edition source (File System Access API plus practice folder). |
| `website/` | Product site and docs, deployed on Vercel (`/`, `/docs/`, `/app/`). |

Live site: https://winshield-web-final.vercel.app

WinShield does not replace Microsoft Defender or a tested backup.

## Download the Windows app

Every push to `main` builds `WinShield.exe` (self-contained, no .NET install needed) and attaches
`WinShield-win-x64.zip` to a GitHub Release (Releases page on this repo). Unzip, run `WinShield.exe`,
create an account, and keep the recovery key somewhere safe. Right-click -> Run as administrator for
process suspension, quarantine and network isolation.

Two downloads are attached to each release:
- `WinShield-small-needs-dotnet8.zip` (a few MB): needs the free [.NET 8 Desktop Runtime](https://dotnet.microsoft.com/download/dotnet/8.0).
- `WinShield-win-x64.zip` (about 65 MB): runs on any Windows 10/11 PC with nothing installed.

Logo and brand assets are in `brand/`.
