// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace AppShield.Native
{
    internal sealed class ContainerIdentity : IDisposable
    {
        internal readonly IntPtr Pointer;
        internal readonly SecurityIdentifier Sid;
        internal readonly string Name;
        internal readonly string Folder;
        internal static string NameFor(Guid id)
        {
            if (id == Guid.Empty) throw new ArgumentException("缺少应用标识。");
            return "AppShield.Native." + id.ToString("N");
        }

        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        private static extern int CreateAppContainerProfile(string name, string display, string description,
            IntPtr capabilities, uint count, out IntPtr sid);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        private static extern int DeriveAppContainerSidFromAppContainerName(string name, out IntPtr sid);
        [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
        private static extern int GetAppContainerFolderPath(string sid, out IntPtr folder);
        [DllImport("advapi32.dll")] private static extern IntPtr FreeSid(IntPtr sid);

        internal ContainerIdentity(Guid id, bool create)
        {
            Name = NameFor(id);
            IntPtr sid = IntPtr.Zero;
            int hr = create ? CreateAppContainerProfile(Name, "AppShield", "AppShield managed application", IntPtr.Zero, 0, out sid)
                            : unchecked((int)0x800700b7);
            if (hr == unchecked((int)0x800700b7))
                hr = DeriveAppContainerSidFromAppContainerName(Name, out sid);
            if (hr < 0) Marshal.ThrowExceptionForHR(hr);
            try
            {
                Sid = new SecurityIdentifier(sid);
                if (create)
                {
                    hr = GetAppContainerFolderPath(Sid.Value, out var ptr);
                    if (hr < 0) Marshal.ThrowExceptionForHR(hr);
                    try { Folder = Marshal.PtrToStringUni(ptr); }
                    finally { Marshal.FreeCoTaskMem(ptr); }
                }
                Pointer = sid;
            }
            catch { FreeSid(sid); throw; }
        }
        public void Dispose() { FreeSid(Pointer); }
    }
}
