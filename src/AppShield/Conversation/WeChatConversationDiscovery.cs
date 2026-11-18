// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Threading;
using System.Windows.Automation;
using AppShield.Model;

namespace AppShield.Conversation
{
    internal sealed class DiscoveredConversation
    {
        internal VisibleConversationState State { get; }
        internal string Title { get; }
        internal string SourceKey { get; }
        internal string Hint { get; }
        internal bool IsPinned { get; }

        internal DiscoveredConversation(VisibleConversationSample metadata)
        {
            State = metadata.State; Title = metadata.Title; SourceKey = metadata.SourceKey;
            Hint = metadata.Hint; IsPinned = metadata.IsPinned;
        }
    }

    internal static partial class WeChatVisibleConversation
    {
        internal static DiscoveredConversation Discover(AppProfile profile, CancellationToken cancel = default(CancellationToken)) =>
            new DiscoveredConversation(Sample(profile, null, true, null, null, cancel, true, true));

        internal static VisibleConversationSample ReadDiscovered(AppProfile profile, DiscoveredConversation target,
            CancellationToken cancel = default(CancellationToken))
        {
            if (target == null || target.State != VisibleConversationState.Verified || string.IsNullOrEmpty(target.SourceKey) ||
                string.IsNullOrEmpty(target.Title)) return Wrong();
            return Sample(profile, target.Title, true, target.SourceKey, null, cancel, true);
        }

        internal static VisibleConversationSample ReadCurrent(AppProfile profile, CancellationToken cancel = default(CancellationToken)) =>
            Sample(profile, null, true, null, null, cancel, true);

        private static bool IdentifiesGroup(AutomationElement element) =>
            (element.Current.AutomationId ?? "").IndexOf("@chatroom", StringComparison.OrdinalIgnoreCase) >= 0;

        private static bool ChatPopup(AutomationElement root)
        {
            string id = root.Current.AutomationId ?? "";
            return id.StartsWith("ChatSingleWindow", StringComparison.Ordinal) && id.Length > "ChatSingleWindow".Length &&
                id.IndexOf("@chatroom", StringComparison.OrdinalIgnoreCase) < 0;
        }

        // A foreign foreground window is never inspected. In that case, only a unique
        // certified pinned chat may supply a title, without reading titles to choose one.
        private static IEnumerable<IntPtr> PinnedChatWindows(string path, long imageTime, HashSet<int> pids, Func<bool> active)
        {
            var windows = new List<IntPtr>();
            EnumWindows((h, unused) => {
                if (GetWindowThreadProcessId(h, out int pid) != 0 && pids.Contains(pid) && VisiblePinned(h))
                    windows.Add(h);
                return active();
            }, IntPtr.Zero);
            foreach (var h in windows)
            {
                if (!active()) yield break;
                using (var process = VerifiedProcess(h, path, imageTime, out _, out _))
                {
                    if (process != null && ChatPopup(AutomationElement.FromHandle(h))) yield return h;
                }
            }
        }

        internal static IntPtr SelectCurrentChatWindow(IntPtr foregroundChat, IEnumerable<IntPtr> pinnedChats, out bool ambiguous)
        {
            ambiguous = false;
            if (foregroundChat != IntPtr.Zero) return foregroundChat;
            IntPtr selected = IntPtr.Zero;
            foreach (var candidate in pinnedChats)
            {
                if (selected != IntPtr.Zero && selected != candidate) { ambiguous = true; return IntPtr.Zero; }
                selected = candidate;
            }
            return selected;
        }

        private static VisibleConversationSample InspectCurrentWindow(string path, long imageTime, HashSet<int> pids,
            string expectedTitle, string binding, bool titleOnly, Func<bool> active)
        {
            IntPtr foreground = GetForegroundWindow();
            if (!active() || foreground == IntPtr.Zero) return Inactive();
            GetWindowThreadProcessId(foreground, out int foregroundPid);
            // A foreground WeChat window, including an unrecognized WeChat dialog, takes precedence.
            // Never silently substitute an unrelated pinned conversation for the user's active window.
            bool pinned = !pids.Contains(foregroundPid);
            var window = SelectCurrentChatWindow(pinned ? IntPtr.Zero : foreground,
                PinnedChatWindows(path, imageTime, pids, active), out bool ambiguous);
            if (ambiguous) return Wrong();
            if (window == IntPtr.Zero || !active()) return Inactive();
            using (var process = VerifiedProcess(window, path, imageTime, out int pid, out long birth))
            {
                if (process == null) return Inactive();
                Func<bool> current = () => active() && GetForegroundWindow() == foreground &&
                    (pinned ? VisiblePinned(window) : Visible(window)) &&
                    GetWindowThreadProcessId(window, out int owner) != 0 && owner == pid && WaitForSingleObject(process, 0) == 258;
                if (!current()) return Inactive();
                var result = ReadScoped(AutomationElement.FromHandle(window), pid, expectedTitle, binding, null, window.ToInt64().ToString("X") + "/" + pid + "/" + birth,
                    current, pinned, true, titleOnly);
                if (pinned && result.State == VisibleConversationState.Verified &&
                    SelectCurrentChatWindow(IntPtr.Zero, PinnedChatWindows(path, imageTime, pids, active), out _) != window) return Wrong();
                return current() ? result : Inactive();
            }
        }
    }
}
