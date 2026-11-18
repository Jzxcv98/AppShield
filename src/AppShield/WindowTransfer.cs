// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using AppShield.Model;

namespace AppShield
{
    internal static class WindowTransfer
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct GuiThread
        {
            public int Size, Flags;
            public IntPtr Active, Focus, Capture, MenuOwner, MoveSize, Caret;
            public int Left, Top, Right, Bottom;
        }
        private delegate bool WindowCallback(IntPtr window, IntPtr data);
        [DllImport("user32.dll")] private static extern bool EnumWindows(WindowCallback callback, IntPtr data);
        [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out int pid);
        [DllImport("user32.dll")] private static extern bool GetGUIThreadInfo(uint tid, ref GuiThread info);
        [DllImport("user32.dll")] private static extern bool SetForegroundWindow(IntPtr hwnd);
        [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] private static extern IntPtr GetAncestor(IntPtr hwnd, uint flags);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetClassName(IntPtr hwnd, StringBuilder name, int size);
        [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")] private static extern IntPtr GetStyle(IntPtr hwnd, int index);
        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr SendMessageTimeout(IntPtr hwnd, uint msg, IntPtr wp, string text, uint flags, uint timeout, out IntPtr result);

        internal static List<TextTarget> List(IEnumerable<int> processIds)
        {
            var ids = new HashSet<int>(processIds ?? Enumerable.Empty<int>());
            var result = new List<TextTarget>();
            if (ids.Count == 0) return result;
            EnumWindows((hwnd, unused) => {
                GetWindowThreadProcessId(hwnd, out int pid);
                if (!ids.Contains(pid) || !IsWindowVisible(hwnd)) return true;
                try
                {
                    using (var process = Process.GetProcessById(pid))
                        result.Add(new TextTarget { WindowHandle = hwnd.ToInt64(), ProcessId = pid,
                            ProcessStartUtcTicks = process.StartTime.ToUniversalTime().Ticks,
                            Label = "窗口 " + (result.Count + 1) + " · PID " + pid });
                }
                catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException || ex is System.ComponentModel.Win32Exception) { }
                return true;
            }, IntPtr.Zero);
            return result;
        }

        internal static void Paste(TextTarget target, string text)
        {
            if (string.IsNullOrEmpty(text) || text.IndexOf('\0') >= 0 || Encoding.UTF8.GetByteCount(text) > TransferBroker.MaxTextBytes)
                throw new InvalidDataException("请选择不超过 1 MiB 的非空纯文本。");
            var hwnd = new IntPtr(target.WindowHandle);
            using (var proc = Process.GetProcessById(target.ProcessId))
            {
                // Keep a handle to the validated process throughout delivery to prevent PID reuse.
                var handle = proc.Handle;
                uint thread = GetWindowThreadProcessId(hwnd, out int pid);
                if (pid != target.ProcessId || thread == 0 || proc.StartTime.ToUniversalTime().Ticks != target.ProcessStartUtcTicks)
                    throw new InvalidOperationException("无法确认目标窗口，请重新选择。");
                if (GetForegroundWindow() != hwnd)
                {
                    bool requested = SetForegroundWindow(hwnd);
                    if (requested && GetForegroundWindow() != hwnd)
                    {
                        // Foreground activation across input queues may complete
                        // asynchronously. Wait only for this window's queue.
                        SendMessageTimeout(hwnd, 0 /* WM_NULL */, IntPtr.Zero, null, 2, 350, out _);
                    }
                    if (GetForegroundWindow() != hwnd)
                        throw new InvalidOperationException("Windows 未将目标置于前台。请选择目标输入框后重试。");
                }
                var info = new GuiThread { Size = Marshal.SizeOf(typeof(GuiThread)) };
                if (!GetGUIThreadInfo(thread, ref info) || info.Focus == IntPtr.Zero || GetAncestor(info.Focus, 2) != hwnd)
                    throw new InvalidOperationException("请先在目标窗口选中可编辑的文本框。");
                uint focusThread = GetWindowThreadProcessId(info.Focus, out int focusPid);
                var cls = new StringBuilder(256);
                GetClassName(info.Focus, cls, cls.Capacity);
                string name = cls.ToString();
                bool supported = name.Equals("Edit", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("RichEdit20W", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("RICHEDIT50W", StringComparison.OrdinalIgnoreCase);
                if (focusPid != pid || focusThread != thread || !supported || (GetStyle(info.Focus, -16).ToInt64() & (0x20 | 0x800)) != 0)
                    throw new InvalidOperationException("该输入框不支持直接文本投递。可改用 UTF-8 文本副本。");
                if (GetForegroundWindow() != hwnd || GetAncestor(info.Focus, 2) != hwnd ||
                    GetWindowThreadProcessId(info.Focus, out int currentPid) != thread || currentPid != pid)
                    throw new InvalidOperationException("目标窗口已变化，请重新选择。");
                if (SendMessageTimeout(info.Focus, 0x00C2 /* EM_REPLACESEL */, new IntPtr(1), text, 2, 1500, out _) == IntPtr.Zero)
                    throw new InvalidOperationException("目标未及时确认文本操作，请核对输入框后再决定是否重试。");
                GC.KeepAlive(handle);
            }
        }
    }
}
