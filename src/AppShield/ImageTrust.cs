// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace AppShield
{
    internal static class ImageTrust
    {
        internal const string Unsigned = "未签名";
        internal const string Unverified = "无法验证签名";
        internal const string VerifiedPrefix = "已验证签名（本机信任） · ";
        private const int NoSignature = unchecked((int)0x800b0100);
        private static readonly Guid VerifyV2 = new Guid("00aac56b-cd44-11d0-8cc2-00c04fc295ee");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct FileSubject { public uint Size; public string Path; public IntPtr File, KnownSubject; }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CatalogSubject
        {
            public uint Size, Version;
            public string CatalogPath, MemberTag, MemberPath;
            public IntPtr MemberFile, Hash;
            public uint HashLength;
            public IntPtr Context, Admin;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct TrustData
        {
            public uint Size;
            public IntPtr Policy, Sip;
            public uint Ui, Revocation, Choice;
            public IntPtr Subject;
            public uint Action;
            public IntPtr State, Url;
            public uint Flags, UiContext;
            public IntPtr SignatureSettings;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CatalogPath
        {
            public uint Size;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string Path;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeFileHandle ReOpenFile(SafeFileHandle file, uint access, uint share, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetFilePointerEx(SafeFileHandle file, long distance, out long position, uint method);
        [DllImport("wintrust.dll", ExactSpelling = true)]
        private static extern int WinVerifyTrust(IntPtr owner, ref Guid action, ref TrustData data);
        [DllImport("wintrust.dll")] private static extern IntPtr WTHelperProvDataFromStateData(IntPtr state);
        [DllImport("wintrust.dll")] private static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr data, uint i, bool counter, uint j);
        [DllImport("wintrust.dll")] private static extern IntPtr WTHelperGetProvCertFromChain(IntPtr signer, uint i);
        [DllImport("wintrust.dll", CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
        private static extern bool CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr system, string algorithm, IntPtr policy, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr admin, SafeFileHandle file, ref uint size, [Out] byte[] hash, uint flags);
        [DllImport("wintrust.dll", SetLastError = true)]
        private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr admin, byte[] hash, uint size, uint flags, IntPtr previous);
        [DllImport("wintrust.dll", ExactSpelling = true)]
        private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalog, ref CatalogPath info, uint flags);
        [DllImport("wintrust.dll")] private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr admin, IntPtr catalog, uint flags);
        [DllImport("wintrust.dll")] private static extern bool CryptCATAdminReleaseContext(IntPtr admin, uint flags);

        internal static string Describe(string path, FileStream lockedImage) => Describe(path, lockedImage, out _);

        internal static string Describe(string path, FileStream lockedImage, out string verifiedSigner)
        {
            verifiedSigner = null;
            // A second handle to the same object keeps hashing independent of the caller's stream position.
            using (var file = ReOpenFile(lockedImage.SafeFileHandle, 0x80000000, 1, 0))
            {
                if (file.IsInvalid) return Unverified;
                try
                {
                    var subject = new FileSubject { Size = Size<FileSubject>(), Path = path, File = file.DangerousGetHandle() };
                    string embedded = Verify(subject, 1, out int status, out verifiedSigner);
                    if (status != NoSignature) return embedded;
                    foreach (var algorithm in new[] { "SHA256", "SHA1" })
                    {
                        string catalog = FromCatalog(path, file, algorithm, out verifiedSigner);
                        if (catalog != null) return catalog;
                    }
                    return HasEmptyCertificateDirectory(lockedImage) ? Unsigned : Unverified;
                }
                catch (CryptographicException) { verifiedSigner = null; return Unverified; }
            }
        }

        private static uint Size<T>() => (uint)Marshal.SizeOf(typeof(T));

        private static bool HasEmptyCertificateDirectory(FileStream image)
        {
            // Some malformed signature tables also produce TRUST_E_NOSIGNATURE. Do not turn
            // an advertised but unreadable Authenticode table into an "unsigned" result.
            long saved = image.Position;
            try
            {
                using (var reader = new BinaryReader(image, System.Text.Encoding.ASCII, true))
                {
                    if (image.Length < 64) return false;
                    image.Position = 60;
                    long pe = reader.ReadInt32();
                    if (pe < 64 || pe > image.Length - 26) return false;
                    image.Position = pe;
                    if (reader.ReadUInt32() != 0x4550) return false;
                    image.Position = pe + 20;
                    int size = reader.ReadUInt16();
                    long optional = pe + 24;
                    image.Position = optional;
                    int magic = reader.ReadUInt16();
                    int directory = magic == 0x10b ? 96 : magic == 0x20b ? 112 : 0;
                    if (directory == 0 || size < directory || optional + size > image.Length) return false;
                    image.Position = optional + directory - 4;
                    if (reader.ReadUInt32() < 5) return true;
                    if (size < directory + 5 * 8) return false;
                    image.Position = optional + directory + 4 * 8;
                    return reader.ReadUInt32() == 0 && reader.ReadUInt32() == 0;
                }
            }
            finally { image.Position = saved; }
        }

        private static string FromCatalog(string path, SafeFileHandle file, string algorithm, out string verifiedSigner)
        {
            verifiedSigner = null;
            if (!CryptCATAdminAcquireContext2(out var admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) return Unverified;
            IntPtr catalog = IntPtr.Zero;
            try
            {
                uint size = algorithm == "SHA256" ? 32u : 20u;
                var hash = new byte[size];
                if (!SetFilePointerEx(file, 0, out _, 0)) return Unverified;
                if (!CryptCATAdminCalcHashFromFileHandle2(admin, file, ref size, hash, 0) || size != hash.Length) return Unverified;
                catalog = CryptCATAdminEnumCatalogFromHash(admin, hash, size, 0, IntPtr.Zero);
                if (catalog == IntPtr.Zero)
                {
                    int error = Marshal.GetLastWin32Error();
                    return error == 0 || error == 1168 || error == unchecked((int)0x80092004) ? null : Unverified;
                }
                var found = new CatalogPath { Size = Size<CatalogPath>() };
                if (!CryptCATCatalogInfoFromContext(catalog, ref found, 0)) return Unverified;
                var pinned = GCHandle.Alloc(hash, GCHandleType.Pinned);
                try
                {
                    var subject = new CatalogSubject { Size = Size<CatalogSubject>(), CatalogPath = found.Path,
                        MemberTag = BitConverter.ToString(hash).Replace("-", ""), MemberPath = path,
                        MemberFile = file.DangerousGetHandle(), Admin = admin, Hash = pinned.AddrOfPinnedObject(), HashLength = size };
                    return Verify(subject, 2, out _, out verifiedSigner);
                }
                finally { pinned.Free(); }
            }
            finally
            {
                if (catalog != IntPtr.Zero) CryptCATAdminReleaseCatalogContext(admin, catalog, 0);
                CryptCATAdminReleaseContext(admin, 0);
            }
        }

        private static string Verify<T>(T subject, uint choice, out int status, out string verifiedSigner) where T : struct
        {
            verifiedSigner = null;
            var memory = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(T)));
            Marshal.StructureToPtr(subject, memory, false);
            var action = VerifyV2;
            // Offline Authenticode policy: no network retrieval or online revocation checks.
            var data = new TrustData { Size = Size<TrustData>(), Ui = 2, Choice = choice, Subject = memory,
                Action = 1, Flags = 0x1000 /* CACHE_ONLY_URL_RETRIEVAL */ | 0x10 /* REVOCATION_CHECK_NONE */ };
            try
            {
                status = WinVerifyTrust(new IntPtr(-1), ref action, ref data);
                if (status != 0) return Unverified;
                IntPtr provider = WTHelperProvDataFromStateData(data.State);
                IntPtr signer = provider == IntPtr.Zero ? IntPtr.Zero : WTHelperGetProvSignerFromChain(provider, 0, false, 0);
                IntPtr cert = signer == IntPtr.Zero ? IntPtr.Zero : WTHelperGetProvCertFromChain(signer, 0);
                // CRYPT_PROVIDER_CERT begins with DWORD cbStruct and an aligned PCCERT_CONTEXT.
                if (cert == IntPtr.Zero || Marshal.ReadInt32(cert) < 2 * IntPtr.Size) return Unverified;
                var context = Marshal.ReadIntPtr(cert, IntPtr.Size);
                if (context == IntPtr.Zero) return Unverified;
                using (var certificate = new X509Certificate2(context))
                {
                    string publisher = certificate.GetNameInfo(X509NameType.SimpleName, false);
                    if (string.IsNullOrWhiteSpace(publisher)) return Unverified;
                    verifiedSigner = publisher;
                    return VerifiedPrefix + publisher;
                }
            }
            finally
            {
                data.Action = 2;
                WinVerifyTrust(new IntPtr(-1), ref action, ref data);
                Marshal.DestroyStructure(memory, typeof(T));
                Marshal.FreeHGlobal(memory);
            }
        }
    }
}
