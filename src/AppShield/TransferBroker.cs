// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AppShield
{
    internal sealed class TransferBroker
    {
        private readonly string root;
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        internal const int MaxTextBytes = 1024 * 1024;
        internal TransferBroker(string root) { this.root = SafeFiles.LocalPath(root); }

        internal string Folder(Guid id, bool incoming)
        {
            if (id == Guid.Empty) throw new InvalidDataException("缺少应用标识。");
            var path = Path.Combine(root, "Transfers", id.ToString("N"), incoming ? "Inbox" : "Outgoing");
            SafeFiles.PlainDirectories(path, true);
            return path;
        }

        internal string Stage(Guid id, string source)
        {
            source = SafeFiles.LocalPath(source);
            using (SafeFiles.PinDirectory(Path.GetDirectoryName(source)))
            using (var input = SafeFiles.OpenRead(source, false))
                return StageStream(id, Path.GetFileName(source), input, ReadZone(source));
        }

        internal string StageText(Guid id, string text)
        {
            if (string.IsNullOrEmpty(text) || text.IndexOf('\0') >= 0 || Utf8.GetByteCount(text) > MaxTextBytes)
                throw new InvalidDataException("请选择不超过 1 MiB 的非空纯文本。");
            using (var input = new MemoryStream(Utf8.GetBytes(text)))
                return StageStream(id, "text.txt", input, null);
        }

        private string StageStream(Guid id, string filename, Stream input, int? zone)
        {
            string outgoing = Folder(id, false);
            var directory = Path.Combine(outgoing, Guid.NewGuid().ToString("N"));
            using (SafeFiles.PinDirectory(outgoing))
            {
                if (!SafeFiles.CreateDirectory(directory, IntPtr.Zero))
                    throw new IOException("无法创建独占中转目录。", new Win32Exception());
                var destination = Path.Combine(directory, filename);
                try { Publish(input, destination, false, zone); }
                catch { Directory.Delete(directory, false); throw; }
                return destination;
            }
        }

        private FileStream OpenIncoming(Guid id, string source)
        {
            source = SafeFiles.LocalPath(source);
            if (!SafeFiles.AtOrBelow(source, Folder(id, true)))
                throw new IOException("只能从这个应用的接收目录导出。");
            return SafeFiles.OpenRead(source, true);
        }

        internal string ReadIncomingText(Guid id, string source)
        {
            if (!string.Equals(Path.GetExtension(source), ".txt", StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("请选择 UTF-8 纯文本文件（.txt）。");
            using (var stream = OpenIncoming(id, source))
            {
                if (stream.Length > MaxTextBytes) throw new InvalidDataException("文本超出 1 MiB。");
                using (var buffer = new MemoryStream())
                {
                    stream.CopyTo(buffer);
                    string text = Utf8.GetString(buffer.ToArray());
                    if (text.Length > 0 && text[0] == '\uFEFF') text = text.Substring(1);
                    if (text.IndexOf('\0') >= 0) throw new InvalidDataException("文件包含二进制数据。");
                    return text;
                }
            }
        }

        internal void Export(Guid id, string source, string destination, bool overwrite)
        {
            destination = SafeFiles.LocalPath(destination);
            if (SafeFiles.AtOrBelow(destination, root)) throw new IOException("请选择 AppShield 数据目录以外的保存位置。");
            source = SafeFiles.LocalPath(source);
            using (SafeFiles.PinDirectory(Path.GetDirectoryName(source)))
            using (var input = OpenIncoming(id, source))
                Publish(input, destination, overwrite, Math.Max(3, ReadZone(source) ?? 3));
        }

        private static int? ReadZone(string path)
        {
            const string name = ":Zone.Identifier";
            using (var h = SafeFiles.CreateFile(path + name, 0x80000000, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero))
            {
                if (h.IsInvalid)
                {
                    int err = Marshal.GetLastWin32Error();
                    // Non-NTFS volumes can report ERROR_INVALID_NAME or ERROR_NOT_SUPPORTED.
                    if (SafeFiles.Missing(err) || err == 123 || err == 50) return null;
                    throw new IOException("无法读取所选文件的来源标记。", new Win32Exception(err));
                }
                using (var stream = new FileStream(h, FileAccess.Read))
                using (var reader = new StreamReader(stream, Encoding.UTF8, true))
                {
                    if (stream.Length > 65536) throw new InvalidDataException("文件来源标记过大。");
                    string line;
                    bool inZone = false;
                    int zone = -1;
                    while ((line = reader.ReadLine()) != null)
                    {
                        line = line.Trim();
                        if (line.StartsWith("[", StringComparison.Ordinal))
                            inZone = line.Equals("[ZoneTransfer]", StringComparison.OrdinalIgnoreCase);
                        if (inZone && line.StartsWith("ZoneId=", StringComparison.OrdinalIgnoreCase)
                            && int.TryParse(line.Substring(7), out int parsed) && parsed >= 0 && parsed <= 4)
                            zone = Math.Max(zone, parsed);
                    }
                    // Unknown markers retain a cautious category. URL and referrer fields are
                    // not propagated into the recipient's sandbox or exported copies.
                    return zone < 0 ? 3 : zone;
                }
            }
        }

        internal static void SavePlainText(string destination, string text, bool overwrite)
        {
            if (string.IsNullOrWhiteSpace(text) || text.IndexOf('\0') >= 0 || Utf8.GetByteCount(text) > MaxTextBytes)
                throw new InvalidDataException("请选择不超过 1 MiB 的非空纯文本。");
            using (var input = new MemoryStream(Utf8.GetBytes(text), false))
                Publish(input, SafeFiles.LocalPath(destination), overwrite, null);
        }

        private static void Publish(Stream input, string destination, bool overwrite, int? zone)
        {
            string parent = Path.GetDirectoryName(destination);
            string temp = Path.Combine(parent, ".appshield-" + Guid.NewGuid().ToString("N") + ".tmp");
            using (var directories = SafeFiles.PinDirectory(parent))
            using (var h = SafeFiles.CreateFile(temp, 0x40000000 | 0x00010000, 0, IntPtr.Zero, 1, 0x00200000, IntPtr.Zero))
            {
                if (h.IsInvalid) throw new IOException("无法创建临时文件。", new Win32Exception());
                using (var output = new FileStream(h, FileAccess.Write))
                {
                    try
                    {
                        SafeFiles.CheckHandle(output, temp, true);
                        input.CopyTo(output);
                        output.Flush(true);
                        if (zone.HasValue) WriteZone(temp, zone.Value);
                        Rename(h, destination, overwrite);
                    }
                    catch
                    {
                        // Mark only our original open file for deletion on close.
                        var disposition = new byte[] { 1, 0, 0, 0 };
                        if (!SetFileInformationByHandle(h, 4, disposition, disposition.Length))
                            throw new IOException("无法回收未发布的临时文件。", new Win32Exception());
                        throw;
                    }
                }
            }
        }

        private static void WriteZone(string temp, int zone)
        {
            using (var handle = SafeFiles.CreateFile(temp + ":Zone.Identifier", 0x40000000, 7, IntPtr.Zero, 1, 0, IntPtr.Zero))
            {
                if (handle.IsInvalid) throw new IOException("目标磁盘无法保留下载来源标记。", new Win32Exception());
                using (var marker = new FileStream(handle, FileAccess.Write))
                {
                    var bytes = Encoding.ASCII.GetBytes("[ZoneTransfer]\r\nZoneId=" + zone + "\r\n");
                    marker.Write(bytes, 0, bytes.Length);
                    marker.Flush(true);
                }
            }
        }

        private static void Rename(SafeFileHandle source, string destination, bool overwrite)
        {
            // FILE_RENAME_INFO has a pointer-aligned RootDirectory, followed by DWORD byte
            // count and UTF-16 name. Use the full path while the parent chain is pinned.
            var nameBytes = Encoding.Unicode.GetBytes(@"\\?\" + destination);
            int lengthAt = IntPtr.Size * 2;
            var info = new byte[lengthAt + 4 + nameBytes.Length + 2];
            info[0] = overwrite ? (byte)1 : (byte)0;
            Buffer.BlockCopy(BitConverter.GetBytes(nameBytes.Length), 0, info, lengthAt, 4);
            Buffer.BlockCopy(nameBytes, 0, info, lengthAt + 4, nameBytes.Length);
            if (!SetFileInformationByHandle(source, 3, info, info.Length))
                throw new IOException("无法发布文件，请核对同名文件、占用和目录权限。", new Win32Exception());
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFileInformationByHandle(SafeFileHandle file, int infoClass, byte[] info, int size);
    }
}
