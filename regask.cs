using System;
using System.Text;
using System.Runtime.InteropServices;

public static class RegClass
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    public static extern int RegQueryInfoKey(
        IntPtr hKey,
        StringBuilder lpClass,
        ref int lpcClass,
        IntPtr lpReserved,
        out int subkeys,
        out int subkeyMaxLen,
        out int classMaxLen,
        out int values,
        out int valueMaxLen,
        out int secDescLen,
        out int lastWriteTimeLow,
        out int lastWriteTimeHigh
    );
}