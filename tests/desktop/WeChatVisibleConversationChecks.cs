// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Automation.Peers;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Threading;
using AppShield.Conversation;

internal static class WeChatVisibleConversationChecks
{
    private static void Assert(bool result, string name)
    {
        if (!result) throw new InvalidOperationException("Conversation UIA fixture: " + name);
    }

    internal static void Run()
    {
        const string title = "File Transfer", marker = "fixture repeated marker";
        Assert(ConversationPhoneChecks.IsSyntheticMarker("AS-ABC123-123") &&
            !ConversationPhoneChecks.IsSyntheticMarker("ordinary chat text") &&
            !ConversationPhoneChecks.IsSyntheticMarker("AS-sensitive text"), "phone smoke only accepts synthetic marker format");
        Assert(!WeChatVisibleConversation.IsAllowedTitle("WeChat", true) &&
               !WeChatVisibleConversation.IsAllowedTitle("Unselected fixture", false), "generic or unbound titles rejected");
        var window1 = new IntPtr(11); var window2 = new IntPtr(12);
        Assert(WeChatVisibleConversation.SelectCurrentChatWindow(window1, new[] {window2}, out var ambiguousWindow) == window1 &&
            !ambiguousWindow, "ordinary foreground chat wins over an unrelated pinned chat");
        Assert(WeChatVisibleConversation.SelectCurrentChatWindow(IntPtr.Zero, new[] {window1,window2}, out ambiguousWindow) == IntPtr.Zero &&
            ambiguousWindow, "two pinned chats are ambiguous when WeChat is not foreground");
        Assert(WeChatVisibleConversation.SelectCurrentChatWindow(IntPtr.Zero, new[] {window2}, out ambiguousWindow) == window2 &&
            !ambiguousWindow, "sole verified pinned chat is an optional fallback");
        using (var ready = new ManualResetEventSlim())
        {
            Dispatcher dispatcher = null;
            var thread = new Thread(() => {
                dispatcher = Dispatcher.CurrentDispatcher; ready.Set(); Dispatcher.Run();
            }) { IsBackground = true };
            thread.SetApartmentState(ApartmentState.STA); thread.Start(); ready.Wait();
            Window w = null;
            GroupBox panel = null;
            TextBlock heading = null;
            IntPtr handle = IntPtr.Zero;
            using (var proc = Process.GetCurrentProcess())
            try
            {
                dispatcher.Invoke(() => {
                    // No focus, clipboard, notifications or interaction with other applications.
                    w = new Window { Title=title, ShowActivated=false, ShowInTaskbar=false, Width=340, Height=290,
                        WindowStartupLocation=WindowStartupLocation.Manual, Left=SystemParameters.WorkArea.Left + 8,
                        Top=SystemParameters.WorkArea.Top + 8 };
                    var layout = new StackPanel();
                    var decoy = new ListBox();
                    AutomationProperties.SetName(decoy, "Conversations");
                    decoy.Items.Add(Item(title));
                    layout.Children.Add(decoy);
                    var list = new ListBox();
                    AutomationProperties.SetName(list, "Messages");
                    list.Items.Add(Item(marker)); list.Items.Add(Item(marker));
                    layout.Children.Add(list); w.Content=layout;
                    w.Show(); w.UpdateLayout(); handle = new WindowInteropHelper(w).Handle;
                });
                var root = WaitForWindow(handle);
                Func<string,string,Func<bool>,VisibleConversationSample> read = (bound, find, active) =>
                    WeChatVisibleConversation.ReadScoped(root, proc.Id, title, bound, find, "fixture-window", active);
                var first = read(null, null, () => true);
                Assert(first.State == VisibleConversationState.Verified && first.Lines.Length == 2 &&
                    first.Lines.All(r => r.Text == marker && r.Direction == MessageDirection.Unknown && r.StableId == null),
                    "two identical visible messages kept without guessing their speakers or persistent IDs; " + first.Hint);
                var onlyMarker = read(first.SourceKey, marker, () => true);
                Assert(onlyMarker.MarkerSeen && onlyMarker.Lines.Length == 0, "marker-only probe returned no conversation text");
                Assert(!read(first.SourceKey, "fixture missing marker", () => true).MarkerSeen, "marker must match exactly");
                Assert(read(first.SourceKey + "-different", null, () => true).State == VisibleConversationState.WrongConversation,
                    "a changed source is rejected before fetching body text");
                int calls = 0;
                var interrupted = read(null, null, () => ++calls < 5);
                Assert(interrupted.State != VisibleConversationState.Verified && interrupted.Lines.Length == 0,
                    "losing the foreground discards the entire pending snapshot");
                dispatcher.Invoke(() => {w.Title="WeChat"; w.UpdateLayout();});
                var ambiguous = read(null, null, () => true);
                Assert(ambiguous.State != VisibleConversationState.Verified && ambiguous.Lines.Length == 0,
                    "contact in sidebar cannot establish current chat");
                dispatcher.Invoke(() => {
                    var layout = (StackPanel)w.Content;
                    var list = (ListBox)layout.Children[1]; layout.Children.Remove(list);
                    panel = new GroupBox(); AutomationProperties.SetAutomationId(panel, "ChatPanel");
                    heading = new TextBlock {Text=title};
                    AutomationProperties.SetAutomationId(heading, "ChatTitle"); AutomationProperties.SetName(heading, title);
                    var content = new StackPanel(); content.Children.Add(heading);
                    var listWrapper = new GroupBox { Content=list }; content.Children.Add(listWrapper);
                    panel.Content=content; layout.Children.Add(new GroupBox {Content=panel}); w.Height=420; w.UpdateLayout();
                });
                var main = read(null, marker, () => true);
                Assert(main.State == VisibleConversationState.Verified && main.MarkerSeen, "same scoped panel must contain header and message list; " + main.Hint);
                dispatcher.Invoke(() => {heading.Text="Other synthetic chat"; AutomationProperties.SetName(heading, heading.Text);});
                var switched = read(main.SourceKey, null, () => true);
                Assert(switched.State != VisibleConversationState.Verified && switched.Lines.Length == 0,
                    "retained message list cannot bypass the changed header");
                dispatcher.Invoke(() => {
                    w.Title=title; w.Topmost=true;
                    AutomationProperties.SetAutomationId(w,"ChatSingleWindowfilehelper");
                    var page=new FixtureNode(AutomationControlType.Group,"ChatPage","chat_message_page","");
                    page.Children.Add(new FixtureNode(AutomationControlType.Text,"TitleLabel",
                        "content_view.top_content_view.title_h_view.left_v_view.left_content_v_view.left_ui_.big_title_line_h_view.current_chat_name_label",title));
                    var list=new FixtureNode(AutomationControlType.List,"MessageList","chat_message_list","Messages");
                    page.Children.Add(list);
                    list.Children.Add(new FixtureNode(AutomationControlType.ListItem,"TimeRow","","timestamp fixture"));
                    const string bubble="chat_message_list.qt_scrollarea_viewport.chat_bubble_item_view";
                    list.Children.Add(new FixtureNode(AutomationControlType.ListItem,"mmui::ChatTextItemView",bubble,marker));
                    list.Children.Add(new FixtureNode(AutomationControlType.ListItem,"AttachmentView",bubble,"attachment fixture"));
                    list.Children.Add(new FixtureNode(AutomationControlType.ListItem,"mmui::ChatTextItemView",bubble,marker));
                    w.Content=page; w.UpdateLayout();
                });
                Assert(WeChatVisibleConversation.VisiblePinned(handle),"non-activating topmost synthetic window has an uncovered area");
                var pinned=WeChatVisibleConversation.ReadScoped(root,proc.Id,title,null,null,"pinned-fixture",
                    () => WeChatVisibleConversation.VisiblePinned(handle),true);
                Assert(pinned.State==VisibleConversationState.Verified && pinned.Lines.Length==2 && pinned.Lines.All(r=>r.Text==marker),
                    "certified pinned popup admits only exact text bubbles and excludes timestamps and attachments; "+pinned.Hint);
                dispatcher.Invoke(()=>w.Topmost=false);
                Assert(!WeChatVisibleConversation.VisiblePinned(handle),"removing topmost ends the pinned admission");
                Func<string,string,bool,VisibleConversationSample> discover = (expected, bound, meta) =>
                    WeChatVisibleConversation.ReadScoped(root,proc.Id,expected,bound,null,"ordinary-fixture",()=>true,false,true,meta);
                int before = Volatile.Read(ref FixtureNode.BubbleNameReads);
                var popupMeta = discover(null,null,true);
                Assert(popupMeta.State == VisibleConversationState.Verified && !popupMeta.IsPinned &&
                    popupMeta.Title == title && popupMeta.Lines.Length == 0 && before == Volatile.Read(ref FixtureNode.BubbleNameReads),
                    "title-only discovery in an unpinned popup never requests a bubble name");
                var popupText = discover(popupMeta.Title,popupMeta.SourceKey,false);
                Assert(popupText.State == VisibleConversationState.Verified && popupText.Lines.Length == 2 &&
                    popupText.Lines.All(line=>line.Text==marker) && Volatile.Read(ref FixtureNode.BubbleNameReads)>before,
                    "one-time extraction accepts the same ordinary popup");
                Assert(discover(title,popupMeta.SourceKey+"/wrong",false).State != VisibleConversationState.Verified,
                    "one-time extraction rejects stale popup identity");
                dispatcher.Invoke(()=>AutomationProperties.SetAutomationId(w,"ChatSingleWindowsynthetic@chatroom"));
                int beforeGroup = Volatile.Read(ref FixtureNode.BubbleNameReads);
                Assert(discover(null,null,false).State != VisibleConversationState.Verified &&
                    Volatile.Read(ref FixtureNode.BubbleNameReads) == beforeGroup, "explicit group identifier never admits bubble text");
                FixtureNode actualHeader=null;
                dispatcher.Invoke(()=>{
                    var page=(FixtureNode)w.Content;
                    actualHeader=(FixtureNode)page.Children[0];
                    w.Content=null; w.Title="WeChat"; AutomationProperties.SetAutomationId(w,"");
                    var both=new StackPanel();
                    var master=new FixtureNode(AutomationControlType.Group,"mmui::ChatMasterView","","");
                    var sidePage=new FixtureNode(AutomationControlType.Group,"ChatPage","chat_message_page","");
                    sidePage.Children.Add(new FixtureNode(AutomationControlType.Text,"TitleLabel",
                        "content_view.top_content_view.title_h_view.left_v_view.left_content_v_view.left_ui_.big_title_line_h_view.current_chat_name_label",title));
                    master.Children.Add(sidePage); both.Children.Add(master);
                    var detail=new FixtureNode(AutomationControlType.Group,"mmui::ChatDetailView","","");
                    detail.Children.Add(page); both.Children.Add(detail); w.Content=both;w.UpdateLayout();
                });
                var fixedMain=read(null,null,()=>true);
                Assert(fixedMain.State==VisibleConversationState.Verified && fixedMain.Lines.Length==2 &&
                    fixedMain.Lines.All(r=>r.Text==marker),"certified main chat is scoped to its single detail view");
                var mainMeta = discover(null,null,true);
                Assert(mainMeta.State == VisibleConversationState.Verified && mainMeta.Title == title && mainMeta.Lines.Length == 0,
                    "an unpinned main window discovers the current detail header without message rows");
                Assert(discover(mainMeta.Title,mainMeta.SourceKey,false).Lines.Length == 2 &&
                    discover(popupMeta.Title,popupMeta.SourceKey,false).State != VisibleConversationState.Verified,
                    "matching main source permits extraction and a popup key cannot bind the main frame");
                dispatcher.Invoke(()=>AutomationProperties.SetName(actualHeader,"Other synthetic chat"));
                var sidebarOnly=read(fixedMain.SourceKey,null,()=>true);
                Assert(sidebarOnly.State!=VisibleConversationState.Verified && sidebarOnly.Lines.Length==0,
                    "a matching title in the real-style master panel never authorizes another detail panel");
                var changed = discover(mainMeta.Title,mainMeta.SourceKey,false);
                var next = discover(null,null,true);
                Assert(changed.State == VisibleConversationState.WrongConversation && changed.Lines.Length == 0 &&
                    next.Title=="Other synthetic chat" && next.Lines.Length==0,
                    "changed main header rejects an earlier discovery despite a same-name sidebar title");
                dispatcher.Invoke(()=>AutomationProperties.SetName(actualHeader,"WeChat"));
                int beforeExcluded = Volatile.Read(ref FixtureNode.BubbleNameReads);
                var excluded = discover(null,null,false);
                Assert(excluded.State==VisibleConversationState.Excluded && excluded.Title==null && excluded.Lines.Length==0 &&
                    Volatile.Read(ref FixtureNode.BubbleNameReads) == beforeExcluded,
                    "an ineligible active header is rejected before requesting a single bubble");
                dispatcher.Invoke(()=>AutomationProperties.SetAutomationId(actualHeader,"unrecognized"));
                Assert(discover(null,null,false).Lines.Length==0 &&
                    discover(null,null,true).State!=VisibleConversationState.Verified,
                    "missing structural header never falls back to a sidebar name");
                Console.WriteLine("PASS scoped conversation UIA: unpinned title-only discovery, selected foreground over pinned, ambiguous fallback rejected, main and pop-out text, sidebar isolation, changed header and source binding");
            }
            finally
            {
                dispatcher.Invoke(() => {if (w != null) w.Close();});
                dispatcher.BeginInvokeShutdown(DispatcherPriority.Send); thread.Join(3000);
            }
        }
    }

    private static ListBoxItem Item(string text)
    {
        var row = new ListBoxItem {Content=text};
        AutomationProperties.SetName(row,text);
        return row;
    }

    private static AutomationElement WaitForWindow(IntPtr handle)
    {
        Assert(handle!=IntPtr.Zero,"synthetic window has a native handle");
        var wait=Stopwatch.StartNew();
        while(true)
        {
            try {return AutomationElement.FromHandle(handle);}
            catch(COMException) when(wait.ElapsedMilliseconds<2200) {Thread.Sleep(60);}
        }
    }

    private sealed class FixtureNode : StackPanel
    {
        internal static int BubbleNameReads;
        private readonly AutomationControlType role;
        private readonly string className;
        internal FixtureNode(AutomationControlType role,string className,string id,string caption)
        {
            this.role=role; this.className=className; MinHeight=20;
            AutomationProperties.SetAutomationId(this,id); AutomationProperties.SetName(this,caption);
        }
        protected override AutomationPeer OnCreateAutomationPeer() => new Peer(this);
        private sealed class Peer : FrameworkElementAutomationPeer
        {
            private readonly FixtureNode node;
            internal Peer(FixtureNode node):base(node) {this.node=node;}
            protected override AutomationControlType GetAutomationControlTypeCore() => node.role;
            protected override string GetClassNameCore() => node.className;
            protected override string GetNameCore()
            {
                if (node.className == "mmui::ChatTextItemView") Interlocked.Increment(ref BubbleNameReads);
                return base.GetNameCore();
            }
            protected override bool IsControlElementCore() => true;
            protected override bool IsContentElementCore() => true;
        }
    }
}
