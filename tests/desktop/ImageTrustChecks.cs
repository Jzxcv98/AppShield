// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using AppShield;

internal static class ImageTrustChecks
{
    internal static void Run()
    {
        string self = typeof(ImageTrustChecks).Assembly.Location;
        using (var file = SafeFiles.OpenImage(self))
            DesktopChecks.Assert(ImageTrust.Describe(self, file) == ImageTrust.Unsigned, "unsigned synthetic EXE has no verified publisher");
        string systemExe = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        using (var file = SafeFiles.OpenImage(systemExe))
        {
            string result = ImageTrust.Describe(systemExe, file);
            DesktopChecks.Assert(result.StartsWith(ImageTrust.VerifiedPrefix, StringComparison.Ordinal) &&
                result.IndexOf("Microsoft", StringComparison.OrdinalIgnoreCase) >= 0, "signed Windows EXE publisher verified by local trust");
        }
    }
}
