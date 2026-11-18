// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AppShield.Trials
{
    // Test-only authorization check over the descriptor of a synthetic regular file.
    // It evaluates the running client's primary token. It does not request a file open on its behalf.
    public static class HostAccountAccessCheck
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct Request
        {
            public uint DesiredAccess;
            public IntPtr PrincipalSelfSid, ObjectTypeList;
            public uint ObjectTypeListLength;
            public IntPtr OptionalArguments;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct Reply
        {
            public uint Count;
            public IntPtr Granted, SaclResults, Error;
        }

        [DllImport("authz.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        private static extern bool AuthzInitializeResourceManager(uint flags, IntPtr access, IntPtr groups, IntPtr free, string name, out IntPtr resourceManager);
        [DllImport("authz.dll", SetLastError = true)]
        private static extern bool AuthzInitializeContextFromToken(uint flags, SafeFileHandle token, IntPtr resourceManager,
            IntPtr expiration, long identifier, IntPtr arguments, out IntPtr context);
        [DllImport("authz.dll", SetLastError = true)]
        private static extern bool AuthzAccessCheck(uint flags, IntPtr context, ref Request request, IntPtr audit,
            byte[] descriptor, IntPtr additionalDescriptors, uint additionalCount, ref Reply reply, IntPtr cachedResult);
        [DllImport("authz.dll")] private static extern bool AuthzFreeResourceManager(IntPtr resourceManager);
        [DllImport("authz.dll")] private static extern bool AuthzFreeContext(IntPtr context);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeFileHandle OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint WaitForSingleObject(SafeFileHandle process, uint ms);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(SafeFileHandle process, out long created, out long exited, out long kernel, out long user);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool QueryFullProcessImageName(SafeFileHandle process, uint flags, StringBuilder path, ref int length);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(SafeFileHandle process, uint rights, out SafeFileHandle token);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(SafeFileHandle token, int type, IntPtr buffer, int size, out int used);

        public static bool CanReadData(Process verifiedProcess, string expectedSid, int expectedSessionId,
            string expectedImage, string syntheticFile)
        {
            if ((File.GetAttributes(syntheticFile) & (FileAttributes.Directory | FileAttributes.ReparsePoint)) != 0)
                throw new IOException("Expected a regular synthetic marker file.");
            byte[] descriptor = File.GetAccessControl(syntheticFile, AccessControlSections.Owner |
                AccessControlSections.Group | AccessControlSections.Access).GetSecurityDescriptorBinaryForm();
            return CanReadData(verifiedProcess, expectedSid, expectedSessionId, expectedImage, descriptor);
        }

        public static bool CanReadData(Process verifiedProcess, string expectedSid, int expectedSessionId,
            string expectedImage, byte[] syntheticFileDescriptor)
        {
            if (verifiedProcess == null || syntheticFileDescriptor == null) throw new ArgumentNullException();
            var descriptor = new RawSecurityDescriptor(syntheticFileDescriptor, 0);
            if (descriptor.Owner == null || descriptor.DiscretionaryAcl == null)
                throw new InvalidDataException("The synthetic file must supply its owner and DACL.");
            // Authz expects object-specific rights. This trial uses ordinary NTFS marker DACLs.
            foreach (GenericAce ace in descriptor.DiscretionaryAcl)
            {
                var known = ace as KnownAce;
                if (known != null && (ace.AceFlags & AceFlags.InheritOnly) == 0 &&
                    ((uint)known.AccessMask & 0xF0000000u) != 0)
                    throw new InvalidDataException("Unexpected unmapped generic rights in synthetic file DACL.");
            }
            long expectedCreation = verifiedProcess.StartTime.ToUniversalTime().ToFileTimeUtc();
            using (var process = OpenProcess(0x101000 /* QUERY_LIMITED_INFORMATION | SYNCHRONIZE */, false, verifiedProcess.Id))
            {
                if (process.IsInvalid) throw new Win32Exception();
                long creation, exit, kernel, user;
                if (!GetProcessTimes(process, out creation, out exit, out kernel, out user)) throw new Win32Exception();
                var path = new StringBuilder(32768);
                int count = path.Capacity;
                if (!QueryFullProcessImageName(process, 0, path, ref count)) throw new Win32Exception();
                if (creation != expectedCreation || !string.Equals(path.ToString(), expectedImage, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("The verified process image or creation time changed.");
                EnsureAlive(process);
                SafeFileHandle token;
                if (!OpenProcessToken(process, 8 /* TOKEN_QUERY */, out token)) throw new Win32Exception();
                using (token)
                {
                    MatchIdentity(token, expectedSid, expectedSessionId);
                    bool allowed = CheckFileDescriptor(token, syntheticFileDescriptor);
                    EnsureAlive(process);
                    return allowed;
                }
            }
        }

        private static void EnsureAlive(SafeFileHandle process)
        {
            uint result = WaitForSingleObject(process, 0);
            if (result == uint.MaxValue) throw new Win32Exception();
            if (result != 258 /* WAIT_TIMEOUT */) throw new InvalidOperationException("The verified client exited.");
        }

        private static void MatchIdentity(SafeFileHandle token, string sid, int session)
        {
            int size;
            GetTokenInformation(token, 1 /* TokenUser */, IntPtr.Zero, 0, out size);
            if (Marshal.GetLastWin32Error() != 122 || size < IntPtr.Size || size > 65536) throw new Win32Exception();
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                int used;
                if (!GetTokenInformation(token, 1, buffer, size, out used)) throw new Win32Exception();
                var owner = new SecurityIdentifier(Marshal.ReadIntPtr(buffer));
                if (!GetTokenInformation(token, 12 /* TokenSessionId */, buffer, size, out used)) throw new Win32Exception();
                if (!owner.Equals(new SecurityIdentifier(sid)) || session <= 0 || Marshal.ReadInt32(buffer) != session)
                    throw new InvalidOperationException("The verified client SID or session changed.");
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }

        private static bool CheckFileDescriptor(SafeFileHandle token, byte[] descriptor)
        {
            IntPtr rm, ctx;
            if (!AuthzInitializeResourceManager(1 /* NO_AUDIT */, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, null, out rm))
                throw new Win32Exception();
            try
            {
                if (!AuthzInitializeContextFromToken(0, token, rm, IntPtr.Zero, 0, IntPtr.Zero, out ctx))
                    throw new Win32Exception();
                try
                {
                    IntPtr buffer = Marshal.AllocHGlobal(12);
                    try
                    {
                        var request = new Request { DesiredAccess = 1 /* FILE_READ_DATA */ };
                        var reply = new Reply { Count = 1, Granted = buffer, SaclResults = IntPtr.Add(buffer, 4), Error = IntPtr.Add(buffer, 8) };
                        if (!AuthzAccessCheck(0, ctx, ref request, IntPtr.Zero, descriptor, IntPtr.Zero, 0, ref reply, IntPtr.Zero))
                            throw new Win32Exception();
                        int error = Marshal.ReadInt32(reply.Error);
                        if (error == 5) return false;
                        if (error != 0) throw new Win32Exception(error);
                        if ((Marshal.ReadInt32(reply.Granted) & 1) == 0) throw new InvalidDataException("Inconsistent Authz access result.");
                        return true;
                    }
                    finally { Marshal.FreeHGlobal(buffer); }
                }
                finally { AuthzFreeContext(ctx); }
            }
            finally { AuthzFreeResourceManager(rm); }
        }
    }
}
