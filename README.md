# PC Cleaner

A portable virus-scan-and-cleanup tool for **Windows 10 / 11**, built as a companion to [Laptop Check](https://github.com/libyan11/laptopchecker). Double-click a launcher, get a Microsoft Defender scan and a safe disk cleanup, and a colour-coded report of what it found and freed.

It uses only what's already built into Windows (Microsoft Defender, DISM, the Recycle Bin) - nothing is downloaded or installed.

| Launcher | What it does |
|---|---|
| `Run-PCCleaner.bat` | Scan + clean in one go (quick Defender scan, temp files, browser cache, Recycle Bin) |
| `Run-VirusScan.bat` | Virus scan only (full Defender scan, start-up items, hosts file check) |
| `Run-DeepClean.bat` | Everything the main cleaner does, plus Windows Update leftovers and an offer to remove `Windows.old` |

## Setup

There is nothing to install - it's just a folder of scripts that runs on the Windows PowerShell 5.1 already built into Windows 10 and 11.

1. Clone this repo, or download it as a zip and extract it.
2. **Unblock it** (only needed if you downloaded a zip): right-click the zip, choose **Properties**, tick **Unblock**, click **OK**, *then* extract it.
3. Double-click the launcher you want and click **Yes** on the administrator prompt. Without admin rights, the Defender scan and system-wide temp cleanup are skipped.
4. The report opens by itself, saved in `PCCleaner\Reports\<date>\report.html`.

## What it does

**Scan**
- Checks Microsoft Defender's status (real-time protection, how old the virus definitions are) and updates the definitions
- Runs a Quick or Full Defender scan and lists any active threat detections
- Lists start-up programs (registry `Run` keys and the Start-up folder) so you can review anything unfamiliar
- Checks the `hosts` file for entries that don't belong there (a common malware redirect trick)

**Clean**
- Empties the Temp folders (`%TEMP%` and, with admin rights, `C:\Windows\Temp`)
- Clears browser cache for Chrome, Edge and Firefox - **only** cache/temp files; saved passwords, cookies and history are left alone
- Empties the Recycle Bin (asks for confirmation first)
- With `-Deep`: runs a Windows Update component-store cleanup (DISM) and offers to delete `Windows.old` (asks for confirmation first, since that removes the ability to roll back to the previous Windows install)

Every run shows how much disk space was freed and saves an HTML report.

## Safety

- Nothing is downloaded or installed - it only calls Windows' own built-in tools.
- Destructive steps (emptying the Recycle Bin, Windows Update cleanup, deleting `Windows.old`) ask for a yes/no confirmation before doing anything, unless you pass `-NoPrompt`.
- Only temp and cache folders are touched - personal files, documents, pictures, cookies, saved passwords and browsing history are never deleted.
- Reports contain details about the PC they ran on, so they're excluded from git by `.gitignore`.

## Removing it

Nothing is installed outside this folder: no registry keys, no scheduled tasks, no services. To remove it, just delete the `PCCleaner` folder.
