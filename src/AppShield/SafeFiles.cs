// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AppShield
{
    internal static class SafeFiles
    {
        internal static string LocalPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path) || path.Length < 3 || !char.IsLetter(path[0]) ||
                path[1] != ':' || (path[2] != '\\' && path[2] != '/') || path.IndexOf(':', 2) >= 0 ||
                path.IndexOfAny(new[] { '\r', '\n', '\0', '*', '?', '"' }) >= 0)
                throw new IOException("请选择本地磁盘上的绝对路径。");
            string full = Path.GetFullPath(path).TrimEndUnlessRoot();
            if (new DriveInfo(Path.GetPathRoot(full)).DriveType == DriveType.Network)
                throw new IOException("请选择本地磁盘上的路径。");
            foreach (string part in full.Substring(3).Split(new[] { '\\' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var device = part.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
                if (device == "CON" || device == "PRN" || device == "AUX" || device == "NUL"
                    || device == "CONIN$" || device == "CONOUT$"
                    || (device.Length == 4 && (device.StartsWith("COM") || device.StartsWith("LPT"))
                        && "0123456789¹²³".IndexOf(device[3]) >= 0)
                    || part.EndsWith(".") || part.EndsWith(" "))
                    throw new IOException("请选择普通文件路径。");
            }
            return full;
        }

        private static string TrimEndUnlessRoot(this string path) =>
            path.Length > 3 ? path.TrimEnd('\\', '/') : path;

        internal static bool AtOrBelow(string path, string root) =>
            path.Equals(root, StringComparison.OrdinalIgnoreCase) ||
            path.StartsWith(root.TrimEnd('\\') + "\\", StringComparison.OrdinalIgnoreCase);

        internal static void PlainDirectories(string path, bool create = false)
        {
            using (PinDirectory(path, create)) { }
        }

        internal sealed class DirectoryLease : IDisposable
        {
            internal readonly Stack<SafeFileHandle> Handles = new Stack<SafeFileHandle>();
            public void Dispose()
            {
                while (Handles.Count > 0) Handles.Pop().Dispose();
            }
        }

        internal static DirectoryLease PinDirectory(string path, bool create = false)
        {
            var parts = new Stack<string>();
            for (var dir = new DirectoryInfo(LocalPath(path)); dir != null; dir = dir.Parent)
                parts.Push(dir.FullName);
            var lease = new DirectoryLease();
            try
            {
                foreach (string part in parts)
                {
                    // Pin each component before descending. OPEN_REPARSE_POINT inspects
                    // the actual directory entry. Excluding delete sharing prevents renames.
                    var h = OpenDirectory(part);
                    if (h.IsInvalid && create && Missing(Marshal.GetLastWin32Error()))
                    {
                        h.Dispose();
                        if (!CreateDirectory(part, IntPtr.Zero) && Marshal.GetLastWin32Error() != 183)
                            throw new IOException("无法创建中转目录。", new Win32Exception());
                        h = OpenDirectory(part);
                    }
                    lease.Handles.Push(h);
                    if (h.IsInvalid || !GetFileInformationByHandle(h, out var info))
                        throw new IOException("无法锁定普通目录。", new Win32Exception());
                    if ((info.Attributes & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint))
                        != (uint)FileAttributes.Directory || !MatchesName(h, part))
                        throw new IOException("目录包含重解析点或发生了变化。");
                }
                return lease;
            }
            catch { lease.Dispose(); throw; }
        }

        private static SafeFileHandle OpenDirectory(string path) =>
            CreateFile(path, 0x80, 1, IntPtr.Zero, 3, 0x02000000 | 0x00200000, IntPtr.Zero);
        internal static bool Missing(int error) => error == 2 || error == 3;

        internal static SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr templateFile) =>
            CreateFileW(@"\\?\" + path, access, share, security, creation, flags, templateFile);
        internal static bool CreateDirectory(string path, IntPtr security) => CreateDirectoryW(@"\\?\" + path, security);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security,
            uint creation, uint flags, IntPtr templateFile);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool CreateDirectoryW(string path, IntPtr security);

        [StructLayout(LayoutKind.Sequential)]
        private struct FileInfoNative
        {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Created, Accessed, Written;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle h, out FileInfoNative info);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetFinalPathNameByHandle(SafeFileHandle h, StringBuilder name, uint count, uint flags);

        private static bool MatchesName(SafeFileHandle handle, string expected)
        {
            var name = new StringBuilder(32768);
            uint length = GetFinalPathNameByHandle(handle, name, (uint)name.Capacity, 0);
            if (length == 0 || length >= name.Capacity)
                throw new IOException("无法核对打开的文件对象。", new Win32Exception());
            string actual = name.ToString();
            if (actual.StartsWith(@"\\?\", StringComparison.Ordinal)) actual = actual.Substring(4);
            return string.Equals(actual.TrimEndUnlessRoot(), expected, StringComparison.OrdinalIgnoreCase);
        }

        internal static void CheckHandle(FileStream stream, string expected, bool rejectHardlinks)
        {
            CheckFileHandle(stream.SafeFileHandle, expected, rejectHardlinks);
        }

        private static void CheckFileHandle(SafeFileHandle handle, string expected, bool rejectHardlinks)
        {
            if (!GetFileInformationByHandle(handle, out var info))
                throw new IOException("无法核对打开的文件对象。", new Win32Exception());
            if (!MatchesName(handle, expected) ||
                (rejectHardlinks && info.Links != 1) ||
                (info.Attributes & (uint)(FileAttributes.ReparsePoint | FileAttributes.Directory)) != 0)
                throw new IOException("文件指向了其他位置或存在多个硬链接，无法安全中转。");
        }

        internal static SafeFileHandle PinFileMetadata(string input)
        {
            string path = LocalPath(input);
            using (PinDirectory(Path.GetDirectoryName(path)))
            {
                // READ_CONTROL | FILE_READ_ATTRIBUTES; permit ordinary reader/writer handles.
                var h = CreateFile(path, 0x00020080, 3, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
                try
                {
                    if (h.IsInvalid) throw new IOException("无法核实所选文件的权限。", new Win32Exception());
                    CheckFileHandle(h, path, true);
                    return h;
                }
                catch { h.Dispose(); throw; }
            }
        }

        internal static string DirectoryIdentity(DirectoryLease lease)
        {
            return DirectoryIdentity(lease.Handles.Peek());
        }

        internal static string DirectoryIdentity(SafeFileHandle handle)
        {
            if (!GetFileInformationByHandle(handle, out var info) ||
                (info.Attributes & (uint)(FileAttributes.Directory | FileAttributes.ReparsePoint)) != (uint)FileAttributes.Directory)
                throw new IOException("无法确认授权目录的文件系统标识。",new Win32Exception());
            if ((info.IndexHigh | info.IndexLow) == 0)
                throw new IOException("目录没有可记录的文件系统标识。");
            var fs = new StringBuilder(32);
            if (!GetVolumeInformationByHandleW(handle, IntPtr.Zero, 0, out uint serial, out _, out _, fs, (uint)fs.Capacity) ||
                serial != info.Volume || !string.Equals(fs.ToString(), "NTFS", StringComparison.OrdinalIgnoreCase))
                throw new IOException("此目录没有可用于准确撤销授权的本地 NTFS 身份。");
            return info.Volume.ToString("X8") + "-" + info.IndexHigh.ToString("X8") + info.IndexLow.ToString("X8");
        }

        [StructLayout(LayoutKind.Explicit, Size = 24)]
        private struct FileIdDescriptor
        {
            [FieldOffset(0)] public uint Size;
            [FieldOffset(4)] public int Type; // FileIdType, a 64-bit NTFS file reference
            [FieldOffset(8)] public ulong Id;
        }
        [DllImport("kernel32.dll", ExactSpelling = true, SetLastError = true)]
        private static extern SafeFileHandle OpenFileById(SafeFileHandle hint, ref FileIdDescriptor id, uint access,
            uint share, IntPtr security, uint flags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, IntPtr volumeName, uint nameSize,
            out uint serial, out uint maxComponent, out uint flags, StringBuilder fileSystem, uint capacity);

        private const uint AclAccess = 0x00060080; // READ_CONTROL | WRITE_DAC | FILE_READ_ATTRIBUTES
        private const uint DirectoryFlags = 0x02200000; // BACKUP_SEMANTICS | OPEN_REPARSE_POINT

        internal static SafeFileHandle OpenDirectoryAcl(string path, string identity)
        {
            var handle = CreateFile(path, AclAccess, 3, IntPtr.Zero, 3, DirectoryFlags, IntPtr.Zero);
            return CheckDirectoryAcl(handle, identity);
        }

        private static SafeFileHandle CheckDirectoryAcl(SafeFileHandle handle, string identity)
        {
            try
            {
                if (handle.IsInvalid) throw new IOException("无法打开原授权目录的 ACL。", new Win32Exception());
                if (!string.Equals(DirectoryIdentity(handle), identity, StringComparison.OrdinalIgnoreCase))
                    throw new IOException("目录对象身份不匹配，权限变更已停止。");
                return handle;
            }
            catch { handle.Dispose(); throw; }
        }

        // A null result means NTFS explicitly reported that the file reference is absent
        // on the verified original volume. An unavailable volume or any ambiguous error throws.
        internal static SafeFileHandle OpenRecordedDirectory(string oldPath, string identity)
        {
            if (identity == null || identity.Length != 25 || identity[8] != '-' ||
                !uint.TryParse(identity.Substring(0, 8), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out uint volume) ||
                !ulong.TryParse(identity.Substring(9), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out ulong id) || id == 0)
                throw new IOException("缺少可验证的原目录卷号或文件 ID；撤销记录已保留。");
            string root = Path.GetPathRoot(LocalPath(oldPath));
            using (var hint = OpenDirectory(root))
            {
                var fs = new StringBuilder(32);
                if (hint.IsInvalid || !GetVolumeInformationByHandleW(hint, IntPtr.Zero, 0, out uint actualVolume, out _, out _, fs, (uint)fs.Capacity))
                    throw new IOException("原卷当前无法核实；请重新连接原磁盘后重试撤销。", new Win32Exception());
                if (actualVolume != volume || !string.Equals(fs.ToString(), "NTFS", StringComparison.OrdinalIgnoreCase))
                    throw new IOException("原路径所在卷不是记录的 NTFS 卷；未修改当前目录，撤销仍待处理。");
                var descriptor = new FileIdDescriptor {Size = 24, Type = 0, Id = id};
                var handle = OpenFileById(hint, ref descriptor, AclAccess, 3, IntPtr.Zero, DirectoryFlags);
                if (handle.IsInvalid)
                {
                    int err = Marshal.GetLastWin32Error();
                    handle.Dispose();
                    if (err == 2) return null; // ERROR_FILE_NOT_FOUND for the ID, not the old pathname
                    if (err == 87) throw new IOException("NTFS 未能解析记录的目录 ID（Win32 87）。目录可能已删除，但无法确认；未处理同名对象，撤销记录已保留。",
                        new Win32Exception(err));
                    throw new IOException("原卷上的目录 ID 当前无法打开；未修改同名对象，撤销仍待处理。", new Win32Exception(err));
                }
                return CheckDirectoryAcl(handle, identity);
            }
        }

        internal static FileStream OpenRead(string path, bool rejectHardlinks)
        {
            path = LocalPath(path);
            using (PinDirectory(Path.GetDirectoryName(path)))
            {
                var handle = CreateFile(path, 0x80000000, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    var error = new Win32Exception();
                    handle.Dispose();
                    throw new IOException("无法打开所选文件。", error);
                }
                FileStream stream = null;
                try
                {
                    stream = new FileStream(handle, FileAccess.Read);
                    CheckHandle(stream, path, rejectHardlinks);
                    return stream;
                }
                catch { if (stream != null) stream.Dispose(); else handle.Dispose(); throw; }
            }
        }

        // WindowsApps can deny enumeration or opening ancestor directories even though
        // the caller is allowed to open the exact installed image. This handle only
        // supplies image bytes; never use it for checking a writable transfer destination.
        internal static FileStream OpenImage(string input)
        {
            string path=LocalPath(input);
            var handle=CreateFile(path,0x80000000,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
            if(handle.IsInvalid) {
                var error=new Win32Exception();handle.Dispose();throw new IOException("无法打开程序映像。",error);
            }
            var image=new FileStream(handle,FileAccess.Read);
            try { CheckHandle(image,path,false);return image; }
            catch { image.Dispose();throw; }
        }
    }
}
