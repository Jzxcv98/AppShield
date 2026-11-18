// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace AppShield.Native
{
    internal static class WeChatSandboxProcess
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct Startup
        {
            public int Size; public IntPtr Reserved, Desktop, Title;
            public int X, Y, Width, Height, Cols, Rows, Fill, Flags;
            public short Show, ReservedBytes; public IntPtr ReservedPtr, Stdin, Stdout, Stderr;
        }
        [StructLayout(LayoutKind.Sequential)] private struct StartupEx { public Startup Info; public IntPtr Attributes; }
        [StructLayout(LayoutKind.Sequential)] private struct Child { public IntPtr Process, Thread; public int Pid, Tid; }
        [StructLayout(LayoutKind.Sequential)] private struct Security { public int Size; public IntPtr Descriptor; public int Inherit; }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        private static extern bool CreateProcessW(string exe, StringBuilder line, IntPtr ps, IntPtr ts,
            bool inherit, uint flags, IntPtr environment, string directory, ref StartupEx startup, out Child child);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, ref Security security,
            int disposition, int flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool InitializeProcThreadAttributeList(IntPtr list, uint count, uint flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, UIntPtr attribute,
            IntPtr value, UIntPtr bytes, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")] private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool PeekNamedPipe(SafePipeHandle pipe, IntPtr data,
            int dataSize, IntPtr read, out uint available, IntPtr remaining);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern uint WaitForSingleObject(SafeFileHandle process, uint timeout);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool GetExitCodeProcess(SafeFileHandle process, out int code);
        [DllImport("kernel32.dll", SetLastError=true)] private static extern bool TerminateProcess(SafeFileHandle process, uint code);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

        private static string Quote(string argument) => "\"" +
            Regex.Replace(argument, @"(\\*)(""|$)", m => m.Groups[1].Value + m.Groups[1].Value +
                (m.Groups[2].Value == "\"" ? "\\\"" : "")) + "\"";

        private static SafeFileHandle Start(string exe, string[] args, ref StartupEx startup, bool capture)
        {
            var line = new StringBuilder(string.Join(" ", new[]{exe}.Concat(args).Select(Quote)));
            uint flags = 0x08000000 /* CREATE_NO_WINDOW */ | (capture ? 0x00080000u /* EXTENDED_STARTUPINFO_PRESENT */ : 0);
            if (!CreateProcessW(exe,line,IntPtr.Zero,IntPtr.Zero,capture,flags,IntPtr.Zero,Environment.SystemDirectory,ref startup,out var child))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            CloseHandle(child.Thread);
            return new SafeFileHandle(child.Process,true);
        }

        internal static void StartDetached(string exe, params string[] args)
        {
            var startup = new StartupEx { Info = new Startup { Size = Marshal.SizeOf(typeof(Startup)) } };
            // A connected guest desktop can outlive both AppShield and the process capturing its CLI output.
            using (Start(exe,args,ref startup,false)) { }
        }

        internal static string Query(string exe, params string[] args)
        {
            var sa = new Security { Size=Marshal.SizeOf(typeof(Security)), Inherit=1 };
            using (var output = new AnonymousPipeServerStream(PipeDirection.In, HandleInheritability.Inheritable, 16384))
            using (var nul = CreateFileW("NUL",0xc0000000,3,ref sa,3,0,IntPtr.Zero))
            {
                if (nul.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
                var childOutput = output.ClientSafePipeHandle;
                var startup = new StartupEx { Info = new Startup { Size=Marshal.SizeOf(typeof(StartupEx)),
                    Flags=0x100 /* STARTF_USESTDHANDLES */, Stdin=nul.DangerousGetHandle(), Stderr=nul.DangerousGetHandle(), Stdout=childOutput.DangerousGetHandle() } };
                IntPtr bytes = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref bytes);
                if (bytes==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                var attrs = Marshal.AllocHGlobal(bytes);
                var handles = Marshal.AllocHGlobal(2*IntPtr.Size);
                bool initialized = false;
                SafeFileHandle process;
                try
                {
                    initialized = InitializeProcThreadAttributeList(attrs,1,0,ref bytes);
                    if (!initialized) throw new Win32Exception(Marshal.GetLastWin32Error());
                    Marshal.WriteIntPtr(handles,0,startup.Info.Stdout);
                    Marshal.WriteIntPtr(handles,IntPtr.Size,startup.Info.Stdin);
                    if (!UpdateProcThreadAttribute(attrs,0,(UIntPtr)0x20002 /* PROC_THREAD_ATTRIBUTE_HANDLE_LIST */,
                        handles,(UIntPtr)(2*IntPtr.Size),IntPtr.Zero,IntPtr.Zero)) throw new Win32Exception(Marshal.GetLastWin32Error());
                    startup.Attributes = attrs;
                    process = Start(exe,args,ref startup,true);
                }
                finally
                {
                    if (initialized) DeleteProcThreadAttributeList(attrs);
                    Marshal.FreeHGlobal(handles); Marshal.FreeHGlobal(attrs);
                    GC.KeepAlive(nul); GC.KeepAlive(childOutput);
                }
                using (process)
                using (var captured = new MemoryStream())
                {
                    output.DisposeLocalCopyOfClientHandle();
                    var sw = Stopwatch.StartNew();
                    var buffer = new byte[4096];
                    bool finished = false;
                    try
                    {
                        while (true)
                        {
                            if (!PeekNamedPipe(output.SafePipeHandle,IntPtr.Zero,0,IntPtr.Zero,out uint pending,IntPtr.Zero))
                            {
                                int error=Marshal.GetLastWin32Error();
                                if (error!=109 /* ERROR_BROKEN_PIPE */) throw new Win32Exception(error);
                                pending=0;
                            }
                            if (pending>0)
                            {
                                if (captured.Length+pending>65536) throw new InvalidDataException("Windows 沙盒返回的数据超过预期。");
                                int read=output.Read(buffer,0,(int)Math.Min(pending,(uint)buffer.Length));
                                captured.Write(buffer,0,read);
                            }
                            else if (finished) break; // Root's writes are drained. Do not wait on an inherited pipe in its descendants.
                            if (sw.ElapsedMilliseconds>=60000) throw new TimeoutException("等待 Windows 沙盒超时。请先检查沙盒是否已经启动。");
                            uint wait=WaitForSingleObject(process,pending==0 ? 40u : 0u);
                            if (wait==0) finished=true;
                            else if (wait!=258) throw new Win32Exception(Marshal.GetLastWin32Error());
                        }
                        if (!GetExitCodeProcess(process,out var exit)) throw new Win32Exception(Marshal.GetLastWin32Error());
                        if (exit!=0) throw new Win32Exception(exit,"Windows 沙盒 "+args[0]+" 失败（"+exit+"）。请检查组件和现有会话。");
                        return Encoding.UTF8.GetString(captured.ToArray()).TrimStart('\uFEFF');
                    }
                    catch { if (!finished) TerminateProcess(process,1); throw; }
                }
            }
        }
    }
}
