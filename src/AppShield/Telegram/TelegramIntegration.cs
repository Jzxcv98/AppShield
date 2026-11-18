// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;
using System.Threading.Tasks;

namespace AppShield.Telegram
{
    [DataContract]
    public sealed class TelegramInstall
    {
        [DataMember] public string ExecutablePath { get; private set; }
        [DataMember] public string Version { get; private set; }
        [DataMember] public string Publisher { get; private set; }
        [DataMember] public string PackageFamilyName { get; private set; }
        // Full AUMID; useful for identifying packaged installations after updates.
        [DataMember] public string PackageAppId { get; private set; }
    }

    public static class TelegramIntegration
    {
        public static TelegramInstall Detect()
        {
            return Inspect(null);
        }

        public static TelegramInstall Identify(string executablePath)
        {
            if (string.IsNullOrWhiteSpace(executablePath) || executablePath.Length < 3
                || !char.IsLetter(executablePath[0]) || executablePath[1] != ':' ||
                (executablePath[2] != '\\' && executablePath[2] != '/') || executablePath.IndexOf(':', 2) >= 0
                || !string.Equals(Path.GetFileName(executablePath), "Telegram.exe", StringComparison.OrdinalIgnoreCase))
                return null;
            var path = Path.GetFullPath(executablePath);
            return File.Exists(path) ? Inspect(path) : null;
        }

        private static TelegramInstall Inspect(string candidate)
        {
            // The child uses the Windows-supplied Authenticode verifier. A selected path is
            // passed as data in the environment, never as part of the PowerShell source.
            var script = ReadScript("Discover.ps1");
            var system = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess
                ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Sysnative")
                : Environment.SystemDirectory;
            var start = new ProcessStartInfo {
                FileName = Path.Combine(system, @"WindowsPowerShell\v1.0\powershell.exe"),
                Arguments = "-NoLogo -NoProfile -NonInteractive -EncodedCommand " +
                    Convert.ToBase64String(Encoding.Unicode.GetBytes(script)),
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8
            };
            start.EnvironmentVariables["APPSHIELD_TELEGRAM_CANDIDATE"] = candidate ?? "";
            using (var process = Process.Start(start))
            {
                Task<string> output = process.StandardOutput.ReadToEndAsync();
                Task<string> errors = process.StandardError.ReadToEndAsync();
                if (!process.WaitForExit(20000))
                {
                    try { process.Kill(); } catch (InvalidOperationException) { }
                    throw new TimeoutException("Telegram 安装和签名检查超时。");
                }
                Task.WaitAll(output, errors);
                if (process.ExitCode == 3) return null;
                if (process.ExitCode != 0) throw new InvalidOperationException("无法完成 Telegram 安装和签名检查。");
                using (var result = new MemoryStream(Encoding.UTF8.GetBytes(output.Result.Trim())))
                {
                    return (TelegramInstall)new DataContractJsonSerializer(typeof(TelegramInstall)).ReadObject(result);
                }
            }
        }

        private static string ReadScript(string file)
        {
            var assembly = typeof(TelegramIntegration).Assembly;
            var name = assembly.GetManifestResourceNames().Single(s =>
                s.EndsWith(".Telegram." + file, StringComparison.Ordinal));
            using (var stream = assembly.GetManifestResourceStream(name))
            using (var reader = new StreamReader(stream, Encoding.UTF8))
                return reader.ReadToEnd();
        }
    }
}
