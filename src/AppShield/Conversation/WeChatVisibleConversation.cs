// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Automation;
using AppShield.Model;
using AppShield.Native;
using Microsoft.Win32.SafeHandles;

namespace AppShield.Conversation
{
    internal enum VisibleConversationState { Verified, NotForeground, WrongConversation, Unsupported, Excluded }

    internal sealed class VisibleConversationSample
    {
        internal VisibleConversationState State { get; set; }
        internal string Hint { get; set; }
        internal string SourceKey { get; set; }
        internal string Title { get; set; }
        internal bool IsPinned { get; set; }
        internal ConversationLine[] Lines { get; set; } = new ConversationLine[0];
        internal bool MarkerSeen { get; set; }
        // Only fixed structural labels for synthetic test diagnostics. Contains no titles, provider IDs or names.
        internal string Structure { get; set; }
    }

    internal static partial class WeChatVisibleConversation
    {
        internal static readonly IReadOnlyList<string> FileTransferTitles = Array.AsReadOnly(new[] {
            "File Transfer", "File Transfer Assistant", "文件传输助手", "文件傳輸助手", "檔案傳輸助手", "檔案傳輸助理" });
        private static readonly string[] MainTitles = { "WeChat", "Weixin", "微信", "微信电脑版", "微信電腦版" };
        private static readonly string[] ListTitles = { "Messages", "Message list", "Chat messages", "消息", "消息列表", "聊天消息", "訊息", "訊息列表" };
        private static readonly string[] ListIds = { "MessageList", "ChatMessageList", "message_list" };
        private static readonly string[] PanelIds = { "ChatPanel", "ConversationPanel", "chat_panel" };
        private static readonly string[] HeaderIds = { "ChatTitle", "ConversationTitle", "chat_title" };
        private const string FileWindowId = "ChatSingleWindowfilehelper";
        private const string PageId = "chat_message_page", MessageListId = "chat_message_list";
        private const string NameLabelId = "content_view.top_content_view.title_h_view.left_v_view.left_content_v_view.left_ui_.big_title_line_h_view.current_chat_name_label";
        private const string BubbleId = "chat_message_list.qt_scrollarea_viewport.chat_bubble_item_view";
        private const int MaxRows = 48, MaxRowChars = 4000;
        private static int inFlight;

        [DllImport("user32.dll")] private static extern IntPtr GetForegroundWindow();
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out int pid);
        [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
        [DllImport("user32.dll")] private static extern bool IsIconic(IntPtr window);
        [DllImport("user32.dll", EntryPoint="GetWindowLongPtrW")] private static extern IntPtr GetWindowStyle(IntPtr window, int index);
        [DllImport("user32.dll")] private static extern IntPtr MonitorFromWindow(IntPtr window, uint flags);
        [StructLayout(LayoutKind.Sequential)] private struct Rect { internal int Left,Top,Right,Bottom; }
        [StructLayout(LayoutKind.Sequential)] private struct Point { internal int X,Y; }
        [DllImport("user32.dll")] private static extern bool GetWindowRect(IntPtr window,out Rect rect);
        [DllImport("user32.dll")] private static extern IntPtr WindowFromPoint(Point point);
        [DllImport("user32.dll")] private static extern IntPtr GetAncestor(IntPtr window,uint flags);
        [DllImport("dwmapi.dll")] private static extern int DwmGetWindowAttribute(IntPtr window,int attribute,out int value,int size);
        private delegate bool EnumWindowsCallback(IntPtr window, IntPtr data);
        [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsCallback callback, IntPtr data);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern SafeFileHandle OpenProcess(uint rights, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetProcessTimes(SafeFileHandle process,
            out long created, out long exited, out long kernel, out long user);
        [DllImport("kernel32.dll")] private static extern uint WaitForSingleObject(SafeFileHandle process, uint timeout);
        [DllImport("kernel32.dll")] private static extern bool ProcessIdToSessionId(int process,out int session);
        [DllImport("advapi32.dll",SetLastError=true)] private static extern bool OpenProcessToken(SafeFileHandle process,uint rights,out SafeAccessTokenHandle token);

        internal static bool IsAllowedTitle(string title, bool isSelfChat)
        {
            if (string.IsNullOrWhiteSpace(title) || title.Length > 96 || title != title.Trim() ||
                title.Any(c => char.IsControl(c) || char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.Format))
                return false;
            string normalized;
            try { normalized = title.Normalize(NormalizationForm.FormKC); }
            catch (ArgumentException) { return false; }
            if (ConversationSettings.IsExcludedTitle(normalized) || MainTitles.Contains(normalized, StringComparer.OrdinalIgnoreCase)) return false;
            return isSelfChat || FileTransferTitles.Contains(title, StringComparer.Ordinal);
        }

        internal static VisibleConversationSample Read(AppProfile profile, string expectedTitle, bool isSelfChat,
            string sourceKey = null, CancellationToken cancellation = default(CancellationToken)) =>
            Sample(profile, expectedTitle, isSelfChat, sourceKey, null, cancellation);

        // The preflight test asks UIA only for an exact synthetic marker. It never requests message text.
        internal static VisibleConversationSample ProbeMarker(AppProfile profile, string expectedTitle, bool isSelfChat,
            string marker, string sourceKey = null)
        {
            if (string.IsNullOrWhiteSpace(marker) || marker.Length > 120) throw new ArgumentException("测试标记无效。");
            return Sample(profile, expectedTitle, isSelfChat, sourceKey, marker, CancellationToken.None);
        }

        private static VisibleConversationSample Sample(AppProfile profile, string title, bool self, string binding,
            string marker, CancellationToken cancel, bool discoverCurrent = false, bool titleOnly = false)
        {
            if ((!discoverCurrent || title != null) && !IsAllowedTitle(title, self))
                return Stop(VisibleConversationState.Excluded, "此对话不在采集范围内。");
            if (profile == null || !profile.IsWeChat) return Stop(VisibleConversationState.Unsupported, "请先导入官方微信。");
            if (cancel.IsCancellationRequested || Interlocked.CompareExchange(ref inFlight, 1, 0) != 0)
                return Stop(VisibleConversationState.NotForeground, "等待前台微信窗口。");
            var clock = Stopwatch.StartNew();
            Func<bool> active = () => !cancel.IsCancellationRequested && clock.ElapsedMilliseconds < 3000;
            var work = Task.Run(() => {
                try { return InspectForeground(profile, title, binding, marker, active, discoverCurrent, titleOnly); }
                catch (Exception ex) when (ex is ElementNotAvailableException || ex is COMException || ex is Win32Exception ||
                    ex is UnauthorizedAccessException || ex is IOException || ex is InvalidOperationException ||
                    ex is ArgumentException || ex is TimeoutException)
                { return Stop(VisibleConversationState.Unsupported, "无法核实当前聊天区，可以手动提供片段。"); }
                finally { Interlocked.Exchange(ref inFlight, 0); }
            });
            return work.Wait(3200) && active() ? work.Result :
                Stop(VisibleConversationState.Unsupported, "前台界面没有及时响应。");
        }

        private static VisibleConversationSample InspectForeground(AppProfile profile, string title, string binding,
            string marker, Func<bool> active, bool discoverCurrent, bool titleOnly)
        {
            using (SafeFiles.PinDirectory(Path.GetDirectoryName(profile.ExecutablePath)))
            using (var image = SafeFiles.OpenImage(profile.ExecutablePath))
            {
                AppShieldEngine.CheckHash(image, profile);
                ImageTrust.Describe(profile.ExecutablePath, image, out string signer);
                if (!WeChatIntegration.IsOfficialClient(profile.ExecutablePath, FileVersionInfo.GetVersionInfo(profile.ExecutablePath), signer))
                    return Stop(VisibleConversationState.Unsupported, "微信已更新或身份无法核实，请重新导入。");
                long imageTime = File.GetLastWriteTimeUtc(profile.ExecutablePath).ToFileTimeUtc();
                var pids = new HashSet<int>();
                foreach (var p in Process.GetProcessesByName(Path.GetFileNameWithoutExtension(profile.ExecutablePath)))
                    using (p) pids.Add(p.Id);
                if (discoverCurrent)
                    return InspectCurrentWindow(profile.ExecutablePath, imageTime, pids, title, binding, titleOnly, active);
                // Enumerate HWND/PID only in the current interactive desktop's Z order.
                // Do not obtain names, window texts or UIA trees of other processes.
                var pinned = new List<IntPtr>();
                EnumWindows((h,d) => {
                    if (GetWindowThreadProcessId(h,out int owner) != 0 && pids.Contains(owner) && VisiblePinned(h))
                        pinned.Add(h);
                    return active();
                },IntPtr.Zero);
                IntPtr match = IntPtr.Zero;
                foreach (var h in pinned)
                {
                    if (!active()) return Inactive();
                    using (var process = VerifiedProcess(h, profile.ExecutablePath, imageTime,out int pid,out _))
                    {
                        if (process == null) continue;
                        var window = AutomationElement.FromHandle(h);
                        if (window.FindFirst(TreeScope.Element, PinnedTitle(title,pid)) == null) continue;
                        if (match != IntPtr.Zero) return Stop(VisibleConversationState.WrongConversation,"有多个同名置顶窗口，请只保留本次选择的独立对话。");
                        match=h;
                    }
                }
                bool usePinned=match != IntPtr.Zero;
                IntPtr hwnd=usePinned ? match : GetForegroundWindow();
                if (hwnd == IntPtr.Zero || GetWindowThreadProcessId(hwnd,out int checkPid) == 0 || !pids.Contains(checkPid))
                    return Inactive();
                using (var process=VerifiedProcess(hwnd,profile.ExecutablePath,imageTime,out int pid,out long created))
                {
                    if (process == null) return Inactive();
                    var window=AutomationElement.FromHandle(hwnd);
                    Func<bool> current=() => active() && (usePinned ? VisiblePinned(hwnd) : GetForegroundWindow()==hwnd && Visible(hwnd)) &&
                        GetWindowThreadProcessId(hwnd,out int owner)!=0 && owner==pid && WaitForSingleObject(process,0)==258;
                    if (!current() || (usePinned && window.FindFirst(TreeScope.Element,PinnedTitle(title,pid))==null)) return Inactive();
                    return ReadScoped(window,pid,title,binding,marker,hwnd.ToInt64().ToString("X")+"/"+pid+"/"+created,current,usePinned);
                }
            }
        }

        private static SafeFileHandle VerifiedProcess(IntPtr hwnd,string path,long imageTime,out int pid,out long created)
        {
            created=0;
            GetWindowThreadProcessId(hwnd,out pid);
            var process=OpenProcess(0x101000,false,pid);
            try {
                using (var caller=Process.GetCurrentProcess())
                if (!process.IsInvalid && ProcessIdToSessionId(pid,out int session) && session==caller.SessionId &&
                    string.Equals(NativeJob.Image(process.DangerousGetHandle()),path,StringComparison.OrdinalIgnoreCase) &&
                    GetProcessTimes(process,out created,out _,out _,out _) && created >= imageTime &&
                    OpenProcessToken(process,8,out var token))
                using (token) using (var owner=new WindowsIdentity(token.DangerousGetHandle()))
                using (var self=WindowsIdentity.GetCurrent())
                    if (self.User.Equals(owner.User)) return process;
            } catch {process.Dispose(); throw;}
            process.Dispose();return null;
        }

        private static bool Visible(IntPtr hwnd) => IsWindowVisible(hwnd) && !IsIconic(hwnd) &&
            MonitorFromWindow(hwnd,0) != IntPtr.Zero && DwmGetWindowAttribute(hwnd,14,out int cloaked,sizeof(int))==0 && cloaked==0;
        internal static bool VisiblePinned(IntPtr hwnd)
        {
            if (!Visible(hwnd) || (GetWindowStyle(hwnd,-20).ToInt64() & 8)==0 || !GetWindowRect(hwnd,out var r)) return false;
            int width=r.Right-r.Left,height=r.Bottom-r.Top;
            if(width<3 || height<3) return false;
            // A topmost window can itself be covered by another topmost window. Hit-test its
            // on-screen interior; only HWND ancestry is queried, never pixels or window text.
            foreach (int x in new[]{r.Left+width/2,r.Left+width/8,r.Right-width/8})
                foreach(int y in new[]{r.Top+height/2,r.Top+height/8,r.Bottom-height/8})
                    if (GetAncestor(WindowFromPoint(new Point {X=x,Y=y}),2)==hwnd) return true;
            return false;
        }
        private static Condition PinnedTitle(string title,int pid)
        {
            var exact=new AndCondition(new PropertyCondition(AutomationElement.ProcessIdProperty,pid),
                new PropertyCondition(AutomationElement.NameProperty,title),new PropertyCondition(AutomationElement.IsOffscreenProperty,false));
            return FileTransferTitles.Contains(title) ? (Condition)new AndCondition(exact,
                new PropertyCondition(AutomationElement.AutomationIdProperty,FileWindowId)) : exact;
        }

        // Only these two accessibility contracts are accepted: a titled, standalone conversation
        // window; or a separately identified chat panel with its own exact title control.
        // A matching conversation name elsewhere in the main window is never used as an anchor.
        internal static VisibleConversationSample ReadScoped(AutomationElement root, int pid, string title, string binding,
            string marker, string windowKey, Func<bool> current, bool pinnedWindow = false, bool discover = false, bool titleOnly = false)
        {
            var owner = new PropertyCondition(AutomationElement.ProcessIdProperty, pid);
            var visible = new PropertyCondition(AutomationElement.IsOffscreenProperty, false);
            if (!current()) return Inactive();
            AutomationElement scope = root, heading = root, detail = null;
            var pageCondition=new AndCondition(owner,visible,new PropertyCondition(AutomationElement.AutomationIdProperty,PageId));
            var mainTitle = new AndCondition(owner,visible, Names(AutomationElement.NameProperty, MainTitles));
            Condition titleMatch = title == null ? null :
                new AndCondition(owner, visible, new PropertyCondition(AutomationElement.NameProperty, title));
            if (!discover && titleMatch == null) return Wrong();
            bool standalone = discover ? root.FindFirst(TreeScope.Element, mainTitle) == null : root.FindFirst(TreeScope.Element, titleMatch) != null;
            if (discover && standalone && !ChatPopup(root)) return Unsupported("current-popup-unavailable");
            if (!standalone)
            {
                if (pinnedWindow || root.FindFirst(TreeScope.Element,mainTitle)==null) return Wrong();
                var details=root.FindAll(TreeScope.Descendants,new AndCondition(owner,visible,
                    new PropertyCondition(AutomationElement.ClassNameProperty,"mmui::ChatDetailView"),
                    Types(ControlType.Group,ControlType.Pane)));
                if (details.Count>1) return Unsupported("ambiguous-detail-panel");
                if (discover && details.Count == 0) return Unsupported("current-detail-unavailable");
                if (details.Count==1)
                {
                    detail=details[0];
                    if (!InLayout(detail,root,pid)) return Wrong();
                }
            }
            bool fixedLayout=discover || detail!=null || standalone && (pinnedWindow || root.FindFirst(TreeScope.Element,new PropertyCondition(AutomationElement.AutomationIdProperty,FileWindowId))!=null ||
                root.FindFirst(TreeScope.Descendants,pageCondition)!=null);
            if (fixedLayout)
            {
                scope=Unique(detail??root,TreeScope.Descendants,pageCondition);
                if(scope==null || !InLayout(scope,detail??root,pid)) return Unsupported("chat-page-unavailable");
                var headingCondition = new AndCondition(owner, visible, Types(ControlType.Text, ControlType.Header),
                    new PropertyCondition(AutomationElement.AutomationIdProperty, NameLabelId));
                // Discovery requests Name only after proving both header and message list lie in the same certified page.
                heading=Unique(scope,TreeScope.Descendants,discover ? (Condition)headingCondition : new AndCondition(headingCondition,titleMatch));
                if(heading==null || !InLayout(heading,scope,pid)) return Wrong();
            }
            else if (!standalone)
            {
                // Search for the chat pane's structural ID, never for a contact or a message on the window.
                scope = Unique(root, TreeScope.Descendants, new AndCondition(owner, visible,
                    Names(AutomationElement.AutomationIdProperty, PanelIds), Types(ControlType.Pane, ControlType.Group)));
                if (scope == null || !InLayout(scope, root, pid)) return Unsupported("main-panel-unavailable");
                heading = Unique(scope, TreeScope.Descendants, new AndCondition(
                    Names(AutomationElement.AutomationIdProperty, HeaderIds), Types(ControlType.Text,ControlType.Header),
                    titleMatch));
                if (heading == null || !InLayout(heading, scope, pid)) return Wrong();
            }
            if (!current()) return Inactive();
            var listCondition = new AndCondition(owner, visible, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.List),
                fixedLayout ? (Condition)new PropertyCondition(AutomationElement.AutomationIdProperty,MessageListId) :
                new OrCondition(Names(AutomationElement.NameProperty, ListTitles), Names(AutomationElement.AutomationIdProperty, ListIds)));
            // Containers can have anonymous accessibility layout wrappers. The query selects
            // only a message list under the already identified target; it never returns other rows.
            var list = Unique(scope, TreeScope.Descendants, listCondition);
            if (list == null || !InLayout(list, scope, pid))
            {
                if (marker != null && ReferenceEquals(heading,root) && current() && root.FindFirst(TreeScope.Element,titleMatch) != null)
                {
                    // At this point a standalone top-level title has matched. Ask only about visible control roles.
                    bool hasList = root.FindFirst(TreeScope.Descendants, new AndCondition(owner,visible,
                        new PropertyCondition(AutomationElement.ControlTypeProperty,ControlType.List))) != null;
                    return Unsupported(hasList ? "popout-list-without-known-selector" : "popout-no-list-role");
                }
                return Unsupported("message-list-unavailable");
            }
            if (discover)
            {
                if (!current()) return Inactive();
                if (IdentifiesGroup(root) || IdentifiesGroup(scope) || (detail != null && IdentifiesGroup(detail)))
                    return Unsupported("group-chat");
                string detected = heading.Current.Name;
                if (!IsAllowedTitle(detected, true)) return Stop(VisibleConversationState.Excluded, "此对话不能提取。");
                if (title != null && !string.Equals(title, detected, StringComparison.Ordinal)) return Wrong();
                title = detected;
                titleMatch = new AndCondition(owner, visible, new PropertyCondition(AutomationElement.NameProperty, title));
                if (standalone && root.FindFirst(TreeScope.Element, PinnedTitle(title, pid)) == null) return Wrong();
            }
            string source = windowKey + (standalone ? "/popup/" + RuntimeKey(root) : "/main/" + RuntimeKey(detail ?? scope)) +
                "/" + RuntimeKey(scope) + "/" + RuntimeKey(heading) + "/" + RuntimeKey(list);
            if (binding != null && source != binding) return Wrong();
            Func<bool> allowed = () => current() && heading.FindFirst(TreeScope.Element, titleMatch) != null &&
                (standalone ? !fixedLayout || root.FindFirst(TreeScope.Element,PinnedTitle(title,pid))!=null :
                    root.FindFirst(TreeScope.Element,mainTitle)!=null) &&
                (detail==null || InLayout(detail,root,pid)) &&
                (ReferenceEquals(heading, root) || (InLayout(heading, scope, pid) && InLayout(scope, detail??root, pid))) &&
                InLayout(list, scope, pid) && list.FindFirst(TreeScope.Element, listCondition) != null;
            if (!allowed()) return Wrong();
            if (titleOnly)
                return new VisibleConversationSample {State=VisibleConversationState.Verified, Title=title, SourceKey=source,
                    IsPinned=pinnedWindow, Hint="已识别当前对话。"};
            Condition rowCondition = new AndCondition(owner, visible, new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.ListItem));
            if(fixedLayout) rowCondition=new AndCondition(rowCondition,new PropertyCondition(AutomationElement.AutomationIdProperty,BubbleId),
                new PropertyCondition(AutomationElement.ClassNameProperty,"mmui::ChatTextItemView"));
            var rows = list.FindAll(TreeScope.Children, rowCondition);
            var lines = new List<ConversationLine>();
            var markerCondition = marker == null ? null : new PropertyCondition(AutomationElement.NameProperty, marker);
            bool seen = false;
            for (int index = Math.Max(0, rows.Count - MaxRows); index < rows.Count; index++)
            {
                var row = rows[index];
                if (!allowed()) return Wrong();
                // Providers can recycle virtual rows; require the same direct parent even after enumeration.
                if (!IsDirectChild(row, list)) return Wrong();
                if (markerCondition != null)
                {
                    if (row.FindFirst(TreeScope.Element, markerCondition) != null ||
                        row.FindFirst(TreeScope.Children, new AndCondition(owner, visible, markerCondition,
                            new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text))) != null)
                        seen = true;
                    continue;
                }
                string body = row.Current.Name;
                if (string.IsNullOrWhiteSpace(body))
                {
                    var label = Unique(row, TreeScope.Children, new AndCondition(owner, visible,
                        new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text)));
                    if (!allowed()) return Wrong();
                    if (label != null && IsDirectChild(label,row)) body = label.Current.Name;
                }
                if (string.IsNullOrWhiteSpace(body)) return Unsupported();
                if (body.Length > MaxRowChars) return Stop(VisibleConversationState.Unsupported, "消息过长，请手动选择需要的片段。");
                var direction = fixedLayout ? WeChatBubbleSide.Read(list,row,body) : MessageDirection.Unknown;
                if (fixedLayout && direction==MessageDirection.Unknown && allowed())
                    direction=WeChatRenderedBubbleSide.Read(new IntPtr(root.Current.NativeWindowHandle),list,row,allowed);
                if (!allowed()) return Wrong();
                lines.Add(new ConversationLine(direction,body));
            }
            if (!allowed()) return Wrong();
            if (!fixedLayout && rows.Count == 0 && list.FindFirst(TreeScope.Children, visible) != null) return Unsupported();
            return new VisibleConversationSample {State=VisibleConversationState.Verified,
                Hint=pinnedWindow ? "已核实置顶独立聊天窗口。" : "已核实前台聊天区。", SourceKey=source,
                Title=title, IsPinned=pinnedWindow, Lines=lines.ToArray(), MarkerSeen=seen};
        }

        private static string RuntimeKey(AutomationElement element)
        {
            int[] id = element.GetRuntimeId();
            if (id == null || id.Length == 0) throw new InvalidOperationException("无稳定控件标识。");
            return string.Join(".", id);
        }
        private static bool IsDirectChild(AutomationElement child, AutomationElement expected)
        {
            var parent = TreeWalker.ControlViewWalker.GetParent(child);
            return parent != null && Automation.Compare(parent, expected);
        }
        private static bool InLayout(AutomationElement child, AutomationElement expected, int pid)
        {
            var parent = child;
            for (int depth = 0; depth < 16; depth++)
            {
                parent = TreeWalker.ControlViewWalker.GetParent(parent);
                if (parent == null) return false;
                if (Automation.Compare(parent, expected)) return true;
                if (parent.Current.ProcessId != pid) return false;
                if (parent.FindFirst(TreeScope.Element,new PropertyCondition(AutomationElement.ClassNameProperty,"mmui::ChatMasterView"))!=null) return false;
                var type = parent.Current.ControlType;
                if (type == ControlType.List || type == ControlType.ListItem || type == ControlType.DataGrid ||
                    type == ControlType.DataItem || type == ControlType.Table || type == ControlType.Tree ||
                    type == ControlType.TreeItem || type == ControlType.Menu || type == ControlType.MenuItem ||
                    type == ControlType.ComboBox || type == ControlType.Window) return false;
            }
            return false;
        }
        private static Condition Names(AutomationProperty property, string[] names) =>
            new OrCondition(names.Select(n => (Condition)new PropertyCondition(property, n)).ToArray());
        private static Condition Types(params ControlType[] types) => new OrCondition(types.Select(t =>
            (Condition)new PropertyCondition(AutomationElement.ControlTypeProperty, t)).ToArray());
        private static AutomationElement Unique(AutomationElement root, TreeScope depth, Condition condition)
        {
            var matches = root.FindAll(depth, condition);
            return matches.Count == 1 ? matches[0] : null;
        }
        private static VisibleConversationSample Stop(VisibleConversationState state, string hint) =>
            new VisibleConversationSample {State=state, Hint=hint};
        private static VisibleConversationSample Inactive() => Stop(VisibleConversationState.NotForeground, "等待目标对话回到前台或显示为置顶独立窗口。");
        private static VisibleConversationSample Wrong() => Stop(VisibleConversationState.WrongConversation, "当前聊天未通过绑定核对，采集已暂停。");
        private static VisibleConversationSample Unsupported(string structure = null) => new VisibleConversationSample {
            State=VisibleConversationState.Unsupported, Structure=structure,
            Hint="微信没有提供可核实的消息列表。可以打开单独聊天窗口或手动提供片段。" };
    }
}
