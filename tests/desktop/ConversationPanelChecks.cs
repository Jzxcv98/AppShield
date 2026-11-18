// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using AppShield.Conversation;
using AppShield.Model;
using AppShield.UI;

internal static class ConversationPanelChecks
{
    private sealed class FakeApi : HttpMessageHandler
    {
        internal string Payload;
        internal int Requests;
        internal TaskCompletionSource<HttpResponseMessage> Reply;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage message, CancellationToken token)
        {
            var reply = new TaskCompletionSource<HttpResponseMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
            Reply = reply;
            Payload = await message.Content.ReadAsStringAsync().ConfigureAwait(false);
            Interlocked.Increment(ref Requests);
            using (token.Register(() => reply.TrySetCanceled()))
                return await reply.Task.ConfigureAwait(false);
        }
        internal void ReturnDecision(string action, string text)
        {
            // All method inputs are fixed ASCII fixtures.
            string json = "{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\","+
                "\"content\":[{\"type\":\"output_text\",\"text\":\"{\\\"action\\\":\\\""+action+"\\\",\\\"text\\\":\\\""+text+"\\\"}\"}]}]}";
            Reply.SetResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json,Encoding.UTF8,"application/json") });
        }
    }

    private sealed class CountRealRequests : DelegatingHandler
    {
        internal int Requests;
        internal CountRealRequests() : base(new HttpClientHandler { AllowAutoRedirect=false, UseCookies=false, UseDefaultCredentials=false }) { }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancel)
        {
            if (request.RequestUri.Scheme != "https" || request.RequestUri.Host != "api.openai.com" || request.RequestUri.AbsolutePath != "/v1/responses")
                throw new InvalidOperationException("Unexpected real API test destination.");
            Interlocked.Increment(ref Requests);
            return base.SendAsync(request, cancel);
        }
    }

    private static void WaitFor(Func<bool> ready, string detail, int timeoutSeconds = 12)
    {
        var watch = Stopwatch.StartNew();
        while (!ready())
        {
            if (watch.Elapsed.TotalSeconds > timeoutSeconds) throw new Exception("Conversation UI timeout: " + detail);
            var frame = new DispatcherFrame();
            Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.Background, new Action(() => frame.Continue = false));
            Dispatcher.PushFrame(frame);
            Thread.Sleep(12);
        }
    }

    internal static void Run(string directory)
    {
        var previous = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
        int phase = 0;
        string source = "fixture-window";
        Func<AppProfile,string,bool,string,CancellationToken,VisibleConversationSample> reader = (p, title, own, key, token) => {
            token.ThrowIfCancellationRequested();
            if (title != "File Transfer" || own || (key != null && key != source)) throw new Exception("Unexpected bound target.");
            int step = Volatile.Read(ref phase);
            if (step == 2) return new VisibleConversationSample {State=VisibleConversationState.WrongConversation,Hint="fixture changed"};
            var first = new ConversationLine(MessageDirection.Unknown, "fixture.first");
            var second = new ConversationLine(MessageDirection.Outgoing, "fixture.second");
            return new VisibleConversationSample {State=VisibleConversationState.Verified,SourceKey=source,
                Lines=step == 0 ? new[]{first} : new[]{first,second}};
        };
        using (var transport = new FakeApi())
        using (var client = new HttpClient(transport))
        {
            var panel = new ConversationPanel(reader, new ConversationDraftService(client,null), TimeSpan.FromMilliseconds(40));
            var window = new Window {Content=panel, ShowActivated=false, ShowInTaskbar=false,
                WindowStartupLocation=WindowStartupLocation.Manual,Left=-10000,Top=-10000,Width=720,Height=600};
            Button button(string name) => (Button)panel.FindName(name);
            TextBox box(string name) => (TextBox)panel.FindName(name);
            void click(string name)
            {
                if (!button(name).IsEnabled) throw new Exception("Unexpected disabled action: "+name);
                button(name).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            }
            try
            {
                window.Show();
                ((Expander)panel.FindName("LocalHistorySection")).IsExpanded = true;
                ((Expander)panel.FindName("DraftSection")).IsExpanded = true;
                panel.SetContext(directory, new AppProfile { IsWeChat=true,Id=Guid.NewGuid() });
                click("OpenTargetButton");
                click("PreviewButton");
                WaitFor(() => box("CapturePreviewBox").Text.Contains("fixture.first"), "preview");
                DesktopChecks.Assert(box("HistoryBox").Text.Length == 0 && transport.Requests == 0,
                    "preview writes no messages and sends no model request");
                click("ConfirmCaptureButton");
                Volatile.Write(ref phase,1);
                WaitFor(() => box("HistoryBox").Text.Contains("fixture.second"), "incremental input");
                Volatile.Write(ref phase,2);
                WaitFor(() => !button("PauseButton").IsEnabled, "source change pauses capture");
                DesktopChecks.Assert(box("HistoryBox").Text.Contains("方向未知") && transport.Requests == 0,
                    "only the confirmed source is followed; unknown message direction stays unknown");
                box("ManualBox").Text = "fixture.manual";
                click("AddManualButton");
                box("IntentBox").Text = "fixture.intent";
                click("PrepareButton");
                DesktopChecks.Assert(box("RequestBox").Text.Contains("fixture.manual") && transport.Requests == 0,
                    "model context is visible for approval before any HTTP request");
                box("IntentBox").Text = "fixture.intent.changed";
                DesktopChecks.Assert(!button("GenerateButton").IsEnabled, "changing the intent invalidates the preview");
                click("PrepareButton");
                ((PasswordBox)panel.FindName("KeyBox")).Password = "synthetic-ui-key";
                click("GenerateButton");
                WaitFor(() => transport.Payload != null, "explicit request");
                box("DraftBox").Text = "fixture.user-edited";
                transport.ReturnDecision("reply","fixture.generated");
                WaitFor(() => box("AlternativeBox").Text == "fixture.generated", "preserved edit");
                DesktopChecks.Assert(box("DraftBox").Text == "fixture.user-edited" && transport.Requests == 1 &&
                    transport.Payload.Contains("fixture.intent.changed"), "one approved request preserves edits made during generation");
                ((ComboBox)panel.FindName("TargetBox")).SelectedIndex = 3;
                box("SelfNameBox").Text = "WeChat";
                click("OpenTargetButton");
                DesktopChecks.Assert(box("HistoryBox").Text.Length == 0 && !button("AddManualButton").IsEnabled &&
                    !button("PrepareButton").IsEnabled && !button("PreviewButton").IsEnabled,
                    "an ineligible target cannot capture, record manually or draft");
            }
            finally
            {
                panel.Detach();
                window.Close();
                SynchronizationContext.SetSynchronizationContext(previous);
            }
        }
        AutoDraftFlow(directory,false);
        ExportFlow(directory);
    }

    private static void ExportFlow(string directory)
    {
        var previous = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
        var root = Path.Combine(directory, "local-export-only");
        int active = 0, reads = 0, discoveries = 0, captures = 0, mismatch = 0;
        bool replaceOnSave = false;
        string copied = null;
        string path = Path.Combine(directory,"approved-synthetic-export.txt");
        ConversationPanel panel = null;
        Func<AppProfile,CancellationToken,DiscoveredConversation> discover = (p,c) => {
            Interlocked.Increment(ref discoveries);
            int state = Volatile.Read(ref active);
            return new DiscoveredConversation(new VisibleConversationSample {
                State=state==0 ? VisibleConversationState.NotForeground : VisibleConversationState.Verified,
                Title=state==2 ? "Synthetic B" : "Synthetic A", SourceKey="same-ui-controls",Hint="fixture" });
        };
        Func<AppProfile,DiscoveredConversation,CancellationToken,VisibleConversationSample> read = (p,d,c) => {
            Interlocked.Increment(ref reads);
            return new VisibleConversationSample { State=VisibleConversationState.Verified,Title=Volatile.Read(ref mismatch)!=0 ? "changed" : d.Title, SourceKey=d.SourceKey,
                Lines=new[]{new ConversationLine(MessageDirection.Incoming,d.Title+" older body"), new ConversationLine(MessageDirection.Outgoing,"later body")} };
        };
        using (var fake = new FakeApi())
        using (var client = new HttpClient(fake))
        {
            panel = new ConversationPanel((p,t,s,k,c) => {
                Interlocked.Increment(ref captures); return new VisibleConversationSample { State=VisibleConversationState.NotForeground };
            },new ConversationDraftService(client,null),TimeSpan.FromMilliseconds(35),null,discover,read,t => copied=t,() => {
                if (replaceOnSave) ((Button)panel.FindName("ClearTranscriptButton")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                return path;
            });
            var window = new Window {Content=panel,ShowActivated=false,ShowInTaskbar=false,
                WindowStartupLocation=WindowStartupLocation.Manual,Left=-10000,Top=-10000,Width=720,Height=620};
            TextBox box(string name) => (TextBox)panel.FindName(name);
            Button button(string name) => (Button)panel.FindName(name);
            void click(string name) {
                if (!button(name).IsEnabled) throw new Exception("Disabled export action: "+name);
                button(name).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            }
            try
            {
                window.Show();
                panel.SetContext(root,new AppProfile { IsWeChat=true,Id=Guid.NewGuid() });
                var auto = (CheckBox)panel.FindName("IdentifyCurrentCheck");
                DesktopChecks.Assert(auto.IsChecked != true && reads==0 && discoveries==0 && !Directory.Exists(root),
                    "opening extraction does not discover, read, create history or enable automatic preview");
                click("ExtractCurrentButton");
                WaitFor(() => Volatile.Read(ref discoveries)>0,"one-shot waiting");
                Volatile.Write(ref active,1);
                WaitFor(() => box("TranscriptBox").Text.Contains("Synthetic A older body"),"one click captures after returning to WeChat");
                string transcript = box("TranscriptBox").Text;
                DesktopChecks.Assert(reads==1 && copied==null && fake.Requests==0 && captures==0 && !Directory.Exists(root),
                    "preview reads once without clipboard, filesystem, model or history monitoring");
                box("TranscriptBox").Select(transcript.IndexOf("older body", StringComparison.Ordinal),"older body".Length);
                click("CopyTranscriptButton");
                click("SaveTranscriptButton");
                DesktopChecks.Assert(copied=="older body" && File.ReadAllText(path)=="older body","copy and UTF-8 save use exactly the selected preview");
                File.Delete(path);
                replaceOnSave=true;
                click("SaveTranscriptButton");
                DesktopChecks.Assert(!File.Exists(path),"a changed preview cannot be saved after a modal file picker");
                replaceOnSave=false;
                Volatile.Write(ref mismatch,1);
                click("ExtractCurrentButton");
                WaitFor(() => button("ExtractCurrentButton").IsEnabled,"changed-source read finished");
                DesktopChecks.Assert(box("TranscriptBox").Text.Length==0 && !button("CopyTranscriptButton").IsEnabled,
                    "a changed title cannot publish content from a reused source");
                Volatile.Write(ref mismatch,0);
                Volatile.Write(ref active,0);
                int priorReads=reads;
                click("ExtractCurrentButton");
                click("CancelExtractButton");
                WaitFor(() => button("ExtractCurrentButton").IsEnabled,"cancelled one-shot");
                DesktopChecks.Assert(priorReads==reads && box("TranscriptBox").Text.Length==0,"cancelling a pending extraction leaves no content");
                Volatile.Write(ref active,1);
                auto.IsChecked=true;
                WaitFor(() => box("TranscriptBox").Text.Contains("Synthetic A older body"),"auto-preview enters A");
                int repeat = Volatile.Read(ref discoveries);
                WaitFor(() => Volatile.Read(ref discoveries)>repeat+2,"same-source title polling");
                DesktopChecks.Assert(reads==priorReads+1,"automatic preview does not continuously read a still-open conversation");
                Volatile.Write(ref active,2);
                WaitFor(() => box("TranscriptBox").Text.Contains("Synthetic B older body"),"same widgets now belong to B");
                DesktopChecks.Assert(!box("TranscriptBox").Text.Contains("Synthetic A") && reads==priorReads+2,"same UI controls with a different title renew the preview");
                Volatile.Write(ref active,0);
                WaitFor(() => ((TextBlock)panel.FindName("IdentifyStatus")).Text=="fixture","return to AppShield");
                DesktopChecks.Assert(box("TranscriptBox").Text.Contains("Synthetic B"),"a verified snapshot remains available after returning to AppShield");
                Volatile.Write(ref active,2);
                WaitFor(() => Volatile.Read(ref reads)>priorReads+2,"return to the same chat");
                auto.IsChecked=false;
                ((Expander)panel.FindName("LocalHistorySection")).IsExpanded=true;
                click("OpenTargetButton");
                box("ManualBox").Text = "old test question";
                click("AddManualButton");
                box("ManualBox").Text = "new unrelated test";
                click("AddManualButton");
                click("ExportHistoryButton");
                var full = box("TranscriptBox").Text;
                DesktopChecks.Assert(full.Contains("old test question") && full.Contains("new unrelated test"),"local history explicitly previews all saved lines");
                string past=box("HistoryBox").Text;
                box("HistoryBox").Select(past.IndexOf("old test question",StringComparison.Ordinal),"old test question".Length);
                click("ExportHistorySelectionButton");
                DesktopChecks.Assert(box("TranscriptBox").Text.Contains("old test question") && !box("TranscriptBox").Text.Contains("new unrelated test") &&
                    fake.Requests==0 && captures==0,"old excerpt preview excludes newer lines and never calls an API");
            }
            finally
            {
                panel.Detach();
                window.Close();
                SynchronizationContext.SetSynchronizationContext(previous);
            }
        }
    }

    // Separate opt-in entry point: no real WeChat capture, clipboard access or delivery.
    internal static void RunAutoSyntheticApi(string directory) => AutoDraftFlow(directory,true);

    private static void AutoDraftFlow(string directory, bool realApi)
    {
        var prior = SynchronizationContext.Current;
        SynchronizationContext.SetSynchronizationContext(new DispatcherSynchronizationContext(Dispatcher.CurrentDispatcher));
        var fake = realApi ? null : new FakeApi();
        var real = realApi ? new CountRealRequests() : null;
        using (var client = new HttpClient((HttpMessageHandler)fake ?? real) { Timeout=TimeSpan.FromSeconds(60), MaxResponseContentBufferSize=1024*1024 })
        {
            int calls() => realApi ? Volatile.Read(ref real.Requests) : Volatile.Read(ref fake.Requests);
            int phase = 0, samples = 0;
            var messages = new [] {
                new ConversationLine(MessageDirection.Outgoing,"这是一个虚构的排期验收，周五四点可以交初稿。"),
                new ConversationLine(MessageDirection.Incoming,"请问周五四点能交初稿吗？"),
                new ConversationLine(MessageDirection.Incoming,"只要一行确认就好。"),
                new ConversationLine(MessageDirection.Incoming,"fixture.repeat.request"),
                new ConversationLine(MessageDirection.Outgoing,"fixture.already.replied"),
                new ConversationLine(MessageDirection.Unknown,"fixture.direction.uncertain"),
                new ConversationLine(MessageDirection.Incoming,"fixture.question.needs.clarification"),
                new ConversationLine(MessageDirection.Incoming,"fixture.thanks"),
                new ConversationLine(MessageDirection.Incoming,"fixture.new.turn")
            };
            long ticks = DateTime.UtcNow.Ticks;
            Func<DateTime> now = realApi ? (Func<DateTime>)(() => DateTime.UtcNow) : () => new DateTime(Interlocked.Read(ref ticks),DateTimeKind.Utc);
            Func<AppProfile,string,bool,string,CancellationToken,VisibleConversationSample> reader = (p,title,self,key,cancel) => {
                cancel.ThrowIfCancellationRequested();
                if (title != "File Transfer" || self || (key != null && key != "synthetic-auto")) throw new Exception("Wrong synthetic target.");
                int n=Volatile.Read(ref phase);
                Interlocked.Increment(ref samples);
                return n == 9 ? new VisibleConversationSample { State=VisibleConversationState.WrongConversation,Hint="fixture changed" }
                    : new VisibleConversationSample {State=VisibleConversationState.Verified,SourceKey="synthetic-auto",Lines=messages.Take(n+1).ToArray()};
            };
            var settings = realApi ? ConversationSettings.Paths("conversation-assistant.json").FirstOrDefault(File.Exists) : null;
            var panel = new ConversationPanel(reader,new ConversationDraftService(client,settings),
                realApi ? TimeSpan.FromSeconds(3) : TimeSpan.FromMilliseconds(35), now);
            var window = new Window {Content=panel, ShowActivated=false,ShowInTaskbar=false,WindowStartupLocation=WindowStartupLocation.Manual,
                Left=-10000,Top=-10000,Width=720,Height=600};
            Button button(string name) => (Button)panel.FindName(name);
            TextBox box(string name) => (TextBox)panel.FindName(name);
            void click(string name) => button(name).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
            void next(int n)
            {
                Volatile.Write(ref phase,n);
                WaitFor(() => box("HistoryBox").Text.Contains(messages[n].Text),"capture step "+n);
            }
            void stable(double seconds)
            {
                Interlocked.Add(ref ticks,TimeSpan.FromSeconds(seconds).Ticks);
                int count = Volatile.Read(ref samples);
                WaitFor(() => Volatile.Read(ref samples)>=count+2,"two unchanged verified samples");
            }
            try
            {
                window.Show();
                panel.SetContext(directory,new AppProfile { IsWeChat=true,Id=Guid.NewGuid() });
                click("OpenTargetButton");
                box("IntentBox").Text="我已确定能在周五下午四点交初稿，请自然地确认。";
                if (!realApi) ((PasswordBox)panel.FindName("KeyBox")).Password="synthetic-auto-key";
                var consent=(CheckBox)panel.FindName("AutoDraftCheck");
                DesktopChecks.Assert(!consent.IsEnabled && consent.IsChecked==false,"automatic drafting starts unarmed");
                click("PreviewButton");
                WaitFor(() => box("CapturePreviewBox").Text.Contains(messages[0].Text),"known historical frame");
                click("ConfirmCaptureButton");
                consent.IsChecked=true;
                WaitFor(() => ((TextBlock)panel.FindName("AutoState")).Text.StartsWith("已启用",StringComparison.Ordinal),"fresh consent baseline");
                if (!realApi) stable(60);
                DesktopChecks.Assert(calls()==0,"enabling automatic drafting does not submit existing history");
                next(1);
                if (!realApi) stable(8);
                next(2);
                if (!realApi) stable(5);
                DesktopChecks.Assert(calls()==0,"two consecutive incoming messages wait for the full quiet interval");
                if (!realApi) stable(6);
                WaitFor(() => calls()==1,"automatic API call after quiet",30);
                if (realApi)
                {
                    WaitFor(() => !string.IsNullOrWhiteSpace(box("DraftBox").Text) || button("PrepareButton").IsEnabled,
                        "real synthetic auto draft",80);
                    if (string.IsNullOrWhiteSpace(box("DraftBox").Text))
                        throw new InvalidOperationException("No real synthetic reply draft: "+((TextBlock)panel.FindName("DraftStatus")).Text);
                    // Observe unchanged frames beyond another full quiet interval.
                    var unchanged = Stopwatch.StartNew();
                    WaitFor(() => unchanged.Elapsed >= ConversationAutoDraftTrigger.QuietPeriod + TimeSpan.FromSeconds(3),
                        "second quiet interval",20);
                    DesktopChecks.Assert(calls()==1,"production quiet interval yielded one real draft from synthetic messages without reading WeChat");
                    return;
                }
                DesktopChecks.Assert(fake.Payload.Contains(messages[1].Text) && fake.Payload.Contains(messages[2].Text),
                    "one request carries both incoming messages");
                box("DraftBox").Text="fixture.keep.my.edit";
                fake.ReturnDecision("reply","fixture.auto.generated");
                WaitFor(() => box("AlternativeBox").Text=="fixture.auto.generated","automatic alternative");
                stable(60);
                DesktopChecks.Assert(calls()==1 && box("DraftBox").Text=="fixture.keep.my.edit",
                    "unchanged frames do not re-submit and editing survives the automatic result");
                next(3); stable(5); next(4); stable(30); next(5); stable(30);
                DesktopChecks.Assert(calls()==1,"own reply cancels pending draft; unknown direction cannot trigger one");
                next(6); stable(11); WaitFor(() => calls()==2,"clarification request");
                fake.ReturnDecision("clarify","fixture.ask.the.user");
                WaitFor(() => ((TextBlock)panel.FindName("DraftStatus")).Text.Contains("fixture.ask.the.user"),"clarification shown to user");
                next(7); stable(11); WaitFor(() => calls()==3,"no-reply request");
                fake.ReturnDecision("no_reply","fixture.no.response.needed");
                WaitFor(() => ((TextBlock)panel.FindName("DraftStatus")).Text.Contains("fixture.no.response.needed"),"no-reply decision shown to user");
                DesktopChecks.Assert(box("DraftBox").Text=="fixture.keep.my.edit" && box("AlternativeBox").Text.Length==0,
                    "clarifications and no-reply decisions do not become copyable replies");
                next(8);
                Volatile.Write(ref phase,9);
                WaitFor(() => !consent.IsEnabled && consent.IsChecked==false,"automatic consent withdrawn on source loss");
                DesktopChecks.Assert(calls()==3,"source change discards the next pending turn");
                Volatile.Write(ref phase,0);
                click("PreviewButton");
                WaitFor(() => box("CapturePreviewBox").Text.Contains(messages[0].Text),"new confirmed segment");
                click("ConfirmCaptureButton");
                consent.IsChecked=true;
                WaitFor(() => ((TextBlock)panel.FindName("AutoState")).Text.StartsWith("已启用",StringComparison.Ordinal),"new consent baseline");
                Volatile.Write(ref phase,1);
                WaitFor(() => {
                    string text=box("HistoryBox").Text;
                    return text.LastIndexOf(messages[1].Text,StringComparison.Ordinal)>text.LastIndexOf(messages[0].Text,StringComparison.Ordinal);
                },"arrival after rebinding");
                stable(11);
                WaitFor(() => calls()==4,"new automatic request");
                click("PauseButton");
                WaitFor(() => fake.Reply.Task.IsCanceled,"in-flight request cancelled on pause");
                DesktopChecks.Assert(consent.IsChecked==false && box("DraftBox").Text=="fixture.keep.my.edit",
                    "pausing revokes automatic consent and cancels the pending HTTP request without losing the draft");
                Volatile.Write(ref phase,0);
                click("PreviewButton");
                WaitFor(() => box("CapturePreviewBox").Text.Contains(messages[0].Text),"baseline for local export");
                click("ConfirmCaptureButton");
                consent.IsChecked=true;
                WaitFor(() => ((TextBlock)panel.FindName("AutoState")).Text.StartsWith("已启用",StringComparison.Ordinal),"auto enabled before local export");
                next(1); stable(3);
                click("ExportHistoryButton");
                Interlocked.Add(ref ticks,TimeSpan.FromSeconds(20).Ticks);
                var idle = Stopwatch.StartNew();
                WaitFor(() => idle.ElapsedMilliseconds>=180,"quiet period after local export");
                DesktopChecks.Assert(calls()==4 && consent.IsChecked==false && !button("PauseButton").IsEnabled &&
                    box("TranscriptBox").Text.Contains(messages[1].Text),
                    "exporting local history cancels the pending automatic turn and produces only a local preview");
            }
            finally { panel.Detach(); window.Close(); SynchronizationContext.SetSynchronizationContext(prior); }
        }
    }
}
