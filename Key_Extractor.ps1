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
    Start-Process powershell.exe `
        -Verb RunAs `
        -WorkingDirectory $workingDir `
        -ArgumentList @(
            '-NoExit',
            '-ExecutionPolicy', 'Bypass',
            '-File', "`"$scriptPath`""
        )
    exit
}

# Relaunch as SYSTEM via NSudoLC, set working dir first with -SetDirectory
if (-not $isSystem) {
    & $nsudoPath -U:S -P:E powershell.exe -NoExit -ExecutionPolicy Bypass -Command `
        "Set-Location '$workingDir'; & '$scriptPath'"
    exit
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

$JD    = Get-RegClass $hive "System\CurrentControlSet\Control\Lsa\JD"
$GBG   = Get-RegClass $hive "System\CurrentControlSet\Control\Lsa\GBG"
$DATA  = Get-RegClass $hive "System\CurrentControlSet\Control\Lsa\DATA"
$SKEW1 = Get-RegClass $hive "System\CurrentControlSet\Control\Lsa\Skew1"
$hive.Close()

Write-Host "JD=$JD GBG=$GBG DATA=$DATA SKEW1=$SKEW1"

reg export HKLM\SAM test1.reg /y

.\samviewer.exe --jd $JD --skew1 $SKEW1 --gbg $GBG --data $DATA --reg .\test1.reg