# this readme was generated using Claude and is probably not final and not the best
## if you want to help me make a better one i would appreciate it
## testexport.ps1

> **Disclaimer:** This tool is provided for educational and research purposes only.
> The author is not responsible for any misuse or damage caused by this software.
> Use only on systems you own or have explicit written authorization to test.
> Unauthorized use may violate applicable laws.

A PowerShell script that extracts the Windows SAM (Security Account Manager) database and derives the SYSKEY boot key components, then passes them to `samviewer.exe`(credits to @[Endermanch](https://github.com/Endermanch) for this script) for analysis.

## Overview

This script automates the process of:

1. Escalating privileges to **Administrator**, then to **SYSTEM** (via NSudoLC)
2. Reading the four SYSKEY components (`JD`, `GBG`, `DATA`, `Skew1`) from the LSA registry hive using the native `RegQueryInfoKey` Win32 API
3. Exporting the `HKLM\SAM` hive to a `.reg` file
4. Invoking `samviewer.exe` with the extracted key parts and the exported SAM file

## Requirements

| Dependency | Notes |
|---|---|
| Windows OS | Tested on Windows 10/11 |
| PowerShell 5.1+ | Must be run on a machine where execution policy allows, or launched with `-ExecutionPolicy Bypass` |
| [`NSudoLC.exe`](https://github.com/M2Team/NSudo) | Must be in the **same directory** as the script (included in the downloads) |
| `samviewer.exe` | Must be in the **same directory** as the script (included in the downloads) |

## Usage

Download the release and then run:

```
.\testexport.ps1
```

The script handles privilege escalation automatically:

- If not running as **Administrator**, it relaunches itself elevated via `Start-Process -Verb RunAs`.
- If not running as **SYSTEM**, it relaunches itself as SYSTEM via NSudoLC.
- Once running as SYSTEM, it performs the SAM export and key extraction.

> **Note:** PowerShell will stay open after the script finishes (`-NoExit`) so you can review the output.

## How It Works

### Privilege Escalation

```
User → Administrator (UAC prompt) → SYSTEM (NSudoLC)
```

SYSTEM privileges are required to open the protected LSA registry keys (`HKLM\System\CurrentControlSet\Control\Lsa\JD`, `GBG`, `DATA`, `Skew1`).

### SYSKEY Extraction

The four SYSKEY fragments are stored as the **class name** of their respective registry keys — not as values. The script uses the `RegQueryInfoKey` Win32 API (via inline C# / `Add-Type`) to read these class names directly.

The four fragments are:

| Key | Description |
|---|---|
| `JD` | Fragment 1 of the SYSKEY boot key |
| `Skew1` | Fragment 2 |
| `GBG` | Fragment 3 |
| `DATA` | Fragment 4 |

### SAM Export

```powershell
reg export HKLM\SAM test1.reg /y
```

Exports the SAM hive (which contains local user account hashes) to `test1.reg` in the working directory. This requires SYSTEM privileges.

### SAM Viewer

```powershell
.\samviewer.exe --jd $JD --skew1 $SKEW1 --gbg $GBG --data $DATA --reg .\test1.reg
```

The extracted key fragments and SAM export are handed off to `samviewer.exe` for decryption and display.

## Output

The script prints the four SYSKEY components to the console:

```
JD=<hex> GBG=<hex> DATA=<hex> SKEW1=<hex>
```

It then launches `samviewer.exe`, which reads and decodes the SAM database.

## ⚠️ Security & Legal Notice

This script accesses **credential material** stored in the Windows SAM database, including local account password hashes. It is intended for:

- Authorized penetration testing
- Digital forensics and incident response
- Security research in controlled environments

**Do not use this script on systems you do not own or have explicit written permission to test.** Unauthorized access to credential material may violate local laws including the Computer Fraud and Abuse Act (CFAA) and equivalent legislation in other jurisdictions.

## File Structure

```
.
├── testexport.ps1   # This script
├── NSudoLC.exe      # Required: SYSTEM privilege launcher
├── samviewer.exe    # Required: SAM database viewer/decoder
└── test1.reg        # Generated: exported SAM hive (output)
```
