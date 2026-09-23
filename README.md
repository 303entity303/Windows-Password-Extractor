# Key_Extractor.ps1 | Anti-Virus Bypass Added

> **Disclaimer:** This tool is provided for educational and research purposes only.
> The author is not responsible for any misuse or damage caused by this software.
> Use only on systems you own or have explicit written authorization to test.
> Unauthorized use may violate applicable laws.

A PowerShell script that extracts information from the Windows **SAM** (Security Account Manager) database and the **SYSKEY/boot key** components, then passes the collected data to `samviewer.exe` for analysis.

Credits to [Endermanch](https://github.com/Endermanch) for `samviewer.exe`.

## Usage

Download the latest release and run:

```powershell
.\Key_Extractor.ps1
```

You can also right-click the `.ps1` file and select **Run with PowerShell**.

The script handles everything automatically:

* If it is not running as **Administrator**, it asks for elevation through UAC.
* It then relaunches itself as **SYSTEM** using `NSudoLC.exe`.
* It extracts the required SYSKEY components.
* It obtains the SAM data.
* It starts `samviewer.exe` with the extracted data.

> **Note:** It is normal for the script to open around **4–5 PowerShell/Command Prompt windows** while it is running. These windows are part of the automatic privilege escalation and data collection process.
>
> **Do not close them while the script is running.**
>
> The **final window** will contain the final output and information from the tool.

The PowerShell window may remain open after the script finishes so you can review the output.

Everything described below is handled automatically by the script. The sections below are only here to explain what it is doing.

## Overview

The script performs the following steps:

1. Elevates from **Administrator** to **SYSTEM** using `NSudoLC.exe`.
2. Reads the four SYSKEY components from the Windows Registry.
3. Obtains the Windows SAM database.
4. Passes the collected information to `samviewer.exe`.

You do not need to perform these steps manually.

## Antivirus Handling

Some antivirus or security products may block the normal way of obtaining the SAM database.

When this happens, the script can warn you and give you the option to use its alternative acquisition method.

Instead of relying on the normal registry export, the alternative method reads the underlying Windows hive data directly and then continues with the normal analysis process.

### Antivirus Compatibility

| Antivirus          | Status   | Tested by                                       |
| ------------------ | -------- | ----------------------------------------------- |
| Sophos             | ✅ Tested | [303entity303](https://github.com/303entity303) |
| Microsoft Defender | ✅ Tested | [303entity303](https://github.com/303entity303) |

Security software behavior can change between versions, so compatibility is not guaranteed.

If you test the tool with another antivirus product, please report whether it worked through [email](mailto:303entity303@proton.me) or by opening an issue.

## Requirements

| Dependency                                       | Notes                                       |
| ------------------------------------------------ | ------------------------------------------- |
| **Windows 10/11**                                | Required operating system                   |
| **PowerShell 5.1+**                              | Required to run the script                  |
| [`NSudoLC.exe`](https://github.com/M2Team/NSudo) | Must be in the same directory as the script |
| `samviewer.exe`                                  | Must be in the same directory as the script |

Depending on your system's PowerShell execution policy, you may need to allow the script to run.

## Details

### Privilege Escalation

The script automatically goes through the required privilege levels:

```text
User
  ↓
Administrator
  ↓
SYSTEM
```

SYSTEM privileges are required because Windows protects the registry information and files used by this tool.

### SYSKEY Extraction

The four SYSKEY components are stored in the Windows Registry under:

```text
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
```

They are stored as the **class names** of the following registry keys rather than normal registry values:

| Key     | Description      |
| ------- | ---------------- |
| `JD`    | SYSKEY component |
| `Skew1` | SYSKEY component |
| `GBG`   | SYSKEY component |
| `DATA`  | SYSKEY component |

The script reads these values automatically and passes them to `samviewer.exe`.

### SAM Acquisition

Normally, the script attempts to export the SAM with:

```powershell
reg export HKLM\SAM test1.reg /y
```

This produces a `test1.reg` file containing the exported SAM data.

If the normal export is blocked by security software, the script can use its alternative acquisition method instead.

### SAM Viewer

The collected SYSKEY components and SAM data are passed to:

```powershell
.\samviewer.exe --jd $JD --skew1 $SKEW1 --gbg $GBG --data $DATA --reg .\test1.reg
```

`samviewer.exe` then analyzes the collected data.

## Output

The script prints the extracted SYSKEY components to the console:

```text
JD=<hex> GBG=<hex> DATA=<hex> SKEW1=<hex>
```

It then launches `samviewer.exe` for analysis.

Depending on the acquisition method used, a SAM export such as:

```text
test1.reg
```

may also be created.

## Security & Legal Notice

This tool accesses **credential-related information** stored by Windows, including local account password hashes.

Use it only for legitimate purposes such as:

* Authorized penetration testing
* Digital forensics and incident response
* Security research
* Testing in controlled environments

**Do not use this tool on systems you do not own or have explicit permission to test.**

Unauthorized access to credential material may violate applicable laws and organizational policies.

## File Structure

```text
.
├── Key_Extractor.ps1   # Main PowerShell script
├── NSudoLC.exe         # SYSTEM privilege launcher
├── samviewer.exe       # SAM analysis tool
└── test1.reg           # Generated SAM export, when created
```
