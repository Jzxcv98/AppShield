// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using AppShield.Conversation;
using AppShield.Model;

namespace AppShield.UI
{
    public partial class ConversationPanel : UserControl
    {
        private readonly DispatcherTimer sampler;
        private readonly ConversationDraftService drafts;
        private readonly Func<AppProfile, string, bool, string, CancellationToken, VisibleConversationSample> readVisible;
        private readonly ConversationAutoDraftTrigger autoDraft = new ConversationAutoDraftTrigger();
        private readonly Func<DateTime> utcNow;
        private AppProfile profile;
        private string storeRoot, title, sourceKey, approvedPrompt;
        private bool selfChat, tracking, awaitingPreview, sampling, startManualSegment, automaticRequest, autoNeedsBaseline;
        private int targetVersion, captureVersion, autoConsentVersion, draftEdits;
        private ConversationHistory history;
        private ConversationSnapshot snapshot;
        private long previewRevision;
        private VisibleConversationSample preview;
        private CancellationTokenSource request, samplingCancellation;

        public ConversationPanel() : this(WeChatVisibleConversation.Read, new ConversationDraftService(), TimeSpan.FromSeconds(3)) { }

        internal ConversationPanel(Func<AppProfile, string, bool, string, CancellationToken, VisibleConversationSample> reader,
            ConversationDraftService draftService, TimeSpan interval, Func<DateTime> clock = null,
            Func<AppProfile, CancellationToken, DiscoveredConversation> discover = null,
            Func<AppProfile, DiscoveredConversation, CancellationToken, VisibleConversationSample> extract = null,
            Action<string> copyTranscript = null, Func<string> saveDestination = null)
        {
            readVisible = reader;
            drafts = draftService;
            utcNow = clock ?? (() => DateTime.UtcNow);
            sampler = new DispatcherTimer { Interval = interval };
            findConversation = discover ?? WeChatVisibleConversation.Discover;
            readConversation = extract ?? WeChatVisibleConversation.ReadDiscovered;
            copyExport = copyTranscript ?? Clipboard.SetText;
            chooseExportPath = saveDestination ?? PickExportPath;
            identifyTimer = new DispatcherTimer { Interval = interval };
            identifyTimer.Tick += OnIdentifyTick;
            InitializeComponent();
            System.Windows.Input.CommandManager.AddPreviewExecutedHandler(TranscriptBox, OnTranscriptCommand);
            sampler.Tick += OnCaptureTick;
            IsVisibleChanged += (s, e) => {
                if (!(bool)e.NewValue)
                {
                    ResetExtraction();
                    if (history != null)
                    {
                        StopCapture();
                        InvalidatePrompt();
                        CaptureStatus.Text = "采集已暂停。回到此页后可重新预览。";
                    }
                    UpdateActions();
                }
            };
            UpdateActions();
        }

        internal void SetContext(string root, AppProfile selected)
        {
            if (storeRoot == root && selected?.Id == profile?.Id && selected?.ImageHash == profile?.ImageHash) return;
            ResetTarget();
            KeyBox.Clear();
            SelfNameBox.Clear();
            TargetBox.SelectedIndex = 0;
            profile = selected;
            storeRoot = root;
            UpdateActions();
        }

        internal void Detach()
        {
            ResetTarget();
            KeyBox.Clear();
            SelfNameBox.Clear();
            TargetBox.SelectedIndex = 0;
            profile = null;
            storeRoot = null;
            UpdateActions();
        }

        private void ResetTarget()
        {
            ++targetVersion;
            ResetExtraction();
            StopCapture();
            history = null;
            snapshot = null;
            title = null;
            InvalidatePrompt();
            ClearEditor(ManualBox);
            ClearEditor(IntentBox);
            ClearEditor(DraftBox);
            HistoryBox.Clear();
            AlternativeBox.Clear();
            AlternativeArea.Visibility = Visibility.Collapsed;
            DraftStatus.Text = "";
            HistoryLabel.Text = "本机记录";
            CaptureStatus.Text = "选择目标并打开其本地记录。";
        }

        private static void ClearEditor(TextBox box)
        {
            box.IsUndoEnabled = false;
            box.Clear();
            box.IsUndoEnabled = true;
        }

        private void OnTargetEdited(object sender, RoutedEventArgs e)
        {
            if (CopyButton == null) return;
            ResetTarget();
            bool own = TargetBox.SelectedIndex == 3;
            SelfNamePanel.Visibility = own ? Visibility.Visible : Visibility.Collapsed;
            UpdateActions();
        }

        private void OnOpenTarget(object sender, RoutedEventArgs e)
        {
            if (profile == null) return;
            bool own = TargetBox.SelectedIndex == 3;
            string chosen = own ? SelfNameBox.Text.Trim() : (TargetBox.SelectedItem as ComboBoxItem)?.Content as string;
            if (!WeChatVisibleConversation.IsAllowedTitle(chosen, own))
            {
                CaptureStatus.Text = "该名称不能绑定。请核对一对一对话的完整显示名及本机排除设置。";
                return;
            }
            if (history != null && selfChat == own && title == chosen)
            {
                try
                {
                    var fresh = history.Read(title);
                    if (fresh.Revision != snapshot.Revision) { snapshot = fresh; RenderHistory(); ContextChanged(); }
                }
                catch (Exception ex) { CaptureStatus.Text = ex.Message; }
                UpdateActions();
                return;
            }
            ResetTarget();
            try
            {
                OpenHistory(chosen, own);
                title = chosen; selfChat = own;
                RenderHistory();
                CaptureStatus.Text = "已打开“" + title + "”。可预览该对话的可见消息，也可以手动添加选段。";
            }
            catch (Exception ex) { history = null; CaptureStatus.Text = ex.Message; }
            UpdateActions();
        }

        private void StopCapture()
        {
            ++captureVersion;
            sampler.Stop();
            samplingCancellation?.Cancel();
            tracking = awaitingPreview = false;
            if (AutoDraftCheck != null) AutoDraftCheck.IsChecked = false;
            preview = null;
            sourceKey = null;
            if (CapturePreviewArea != null) { CapturePreviewArea.Visibility = Visibility.Collapsed; CapturePreviewBox.Clear(); }
        }

        private void OnStartPreview(object sender, RoutedEventArgs e)
        {
            if (history == null || extracting != null) return;
            IdentifyCurrentCheck.IsChecked = false;
            StopCapture();
            awaitingPreview = true;
            CaptureStatus.Text = "请切回微信，打开“" + title + "”。找到可核对的消息后，请回到此页确认预览。";
            sampler.Start();
            UpdateActions();
        }

        private async void OnCaptureTick(object sender, EventArgs e)
        {
            if (sampling || !IsVisible || history == null || (!awaitingPreview && !tracking)) return;
            int generation = captureVersion;
            int consent = autoConsentVersion;
            long revision = snapshot.Revision;
            var p = profile; string expected = title, source = sourceKey; bool own = selfChat;
            var cancellation = new CancellationTokenSource();
            samplingCancellation = cancellation;
            sampling = true;
            try
            {
                var sample = await Task.Run(() => readVisible(p, expected, own, source, cancellation.Token));
                if (generation != captureVersion || !IsVisible || snapshot.Revision != revision) return;
                if (sample.State != VisibleConversationState.Verified)
                {
                    if (sample.State != VisibleConversationState.NotForeground)
                    {
                        StopCapture();
                        CaptureStatus.Text = sample.Hint + " 已暂停，可手动添加选段。";
                    }
                    else
                    {
                        InterruptAutomaticTurn();
                        CaptureStatus.Text = "等待“" + title + "”显示在微信前台或置顶的独立窗口中。";
                    }
                    return;
                }
                if (string.IsNullOrEmpty(sample.SourceKey) || (tracking && sample.SourceKey != sourceKey))
                {
                    StopCapture();
                    CaptureStatus.Text = "对话来源发生变化，请重新预览并核对。";
                    return;
                }
                if (sample.Lines.Length == 0)
                {
                    InterruptAutomaticTurn();
                    CaptureStatus.Text = "已核对“" + title + "”，等待可识别的消息。";
                    return;
                }
                if (awaitingPreview)
                {
                    sampler.Stop();
                    awaitingPreview = false;
                    preview = sample;
                    previewRevision = revision;
                    CapturePreviewLabel.Text = "来自“" + title + "”的可见消息";
                    CapturePreviewBox.Text = FormatLines(sample.Lines);
                    CapturePreviewArea.Visibility = Visibility.Visible;
                    CaptureStatus.Text = "请核对对象和消息内容，确认后记入本机。";
                }
                else
                {
                    var previous = snapshot;
                    SaveVisible(sample.Lines, revision);
                    CaptureStatus.Text = "正在记录“" + title + "” · 上次核对 " + DateTime.Now.ToString("HH:mm:ss");
                    if (consent == autoConsentVersion) CheckAutomaticTurn(previous);
                }
            }
            catch (Exception ex)
            {
                if (generation == captureVersion) { StopCapture(); CaptureStatus.Text = "已暂停采集。" + ex.Message; }
            }
            finally
            {
                if (samplingCancellation == cancellation) samplingCancellation = null;
                cancellation.Dispose(); sampling = false; UpdateActions();
            }
        }

        private void OnConfirmCapture(object sender, RoutedEventArgs e)
        {
            if (history == null || preview == null) return;
            try
            {
                snapshot = history.BeginSegment(title, preview.Lines, previewRevision);
                RenderHistory();
                ContextChanged();
                sourceKey = preview.SourceKey;
                preview = null;
                CapturePreviewArea.Visibility = Visibility.Collapsed;
                CapturePreviewBox.Clear();
                tracking = true;
                CaptureStatus.Text = "已确认“" + title + "”。返回该微信对话后继续增量记录。";
                sampler.Start();
            }
            catch (Exception ex) { StopCapture(); CaptureStatus.Text = ex.Message; }
            UpdateActions();
        }

        private void OnPause(object sender, RoutedEventArgs e)
        {
            StopCapture();
            CaptureStatus.Text = "采集已暂停，本机记录已保留。";
            UpdateActions();
        }

        private void OnDraftSectionCollapsed(object sender, RoutedEventArgs e)
        {
            if (e.Source != DraftSection || AutoDraftCheck == null) return;
            AutoDraftCheck.IsChecked = false;
            InvalidatePrompt();
            UpdateActions();
        }

        private void OnAutoModeChanged(object sender, RoutedEventArgs e)
        {
            if (AutoState == null) return;
            ++autoConsentVersion;
            InterruptAutomaticTurn();
            if (AutoDraftCheck.IsChecked != true || !tracking || string.IsNullOrEmpty(sourceKey))
            {
                AutoDraftCheck.IsChecked = false;
                AutoState.Visibility = Visibility.Collapsed;
                return;
            }
            AutoState.Visibility = Visibility.Visible;
            AutoState.Text = "已授权“" + title + "”，正在确认当前消息，以便从下一轮来信开始备稿。";
        }

        private void InterruptAutomaticTurn()
        {
            autoDraft.Reset();
            autoNeedsBaseline = true;
            if (!automaticRequest || request == null) return;
            InvalidatePrompt();
            DraftStatus.Text = "本轮自动建议已取消，已有草稿保留。";
        }

        private void CheckAutomaticTurn(ConversationSnapshot previous)
        {
            if (AutoDraftCheck.IsChecked != true || !tracking || string.IsNullOrEmpty(sourceKey)) return;
            if (autoNeedsBaseline)
            {
                autoDraft.Bind(sourceKey, snapshot);
                autoNeedsBaseline = false;
                AutoState.Text = "已启用“" + title + "”的自动备稿。方向未知或本人发送的消息可以手动起草。";
                return;
            }
            var now = utcNow();
            bool changed = autoDraft.Observe(sourceKey, previous, snapshot, now);
            if (changed && automaticRequest && request != null) InvalidatePrompt();
            if (request != null || approvedPrompt != null || !autoDraft.TryTake(sourceKey, snapshot.Revision, now)) return;
            long scheduled = snapshot.Revision;
            try
            {
                string payload = BuildCurrentPrompt();
                if (snapshot.Revision != scheduled || !autoDraft.IsCurrent(sourceKey, scheduled)) { RenderHistory(); InterruptAutomaticTurn(); return; }
                _ = GenerateAsync(payload, true);
            }
            catch (Exception ex) { DraftStatus.Text = ex.Message; }
        }

        private void OnManualAppend(object sender, RoutedEventArgs e)
        {
            if (history == null || string.IsNullOrWhiteSpace(ManualBox.Text)) return;
            try
            {
                StopCapture();
                AppendManual(ManualBox.Text, DirectionBox.SelectedIndex);
                ManualBox.Clear();
                RenderHistory();
                ContextChanged();
                CaptureStatus.Text = "选段已记入“" + title + "”。如需继续采集，可重新预览。";
            }
            catch (Exception ex) { CaptureStatus.Text = ex.Message; }
            UpdateActions();
        }

        private void OnDelete(object sender, RoutedEventArgs e)
        {
            if (history == null) return;
            if (MessageBox.Show(Window.GetWindow(this), "清除“" + title + "”的全部本机记录及当前草稿？", "清除本机记录",
                MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
            StopCapture();
            InvalidatePrompt();
            try
            {
                DeleteHistory();
                ResetTarget();
                CaptureStatus.Text = "本机对话记录已清除。";
            }
            catch (Exception ex) { CaptureStatus.Text = ex.Message; }
            UpdateActions();
        }

        private void ContextChanged()
        {
            bool old = approvedPrompt != null || request != null || !string.IsNullOrEmpty(DraftBox.Text);
            InvalidatePrompt();
            if (old) DraftStatus.Text = "对话已有更新。当前草稿保留，可重新预览最新上下文。";
        }

        private void InvalidatePrompt()
        {
            if (request != null) { var old = request; request = null; automaticRequest = false; old.Cancel(); }
            approvedPrompt = null;
            RequestArea.Visibility = Visibility.Collapsed;
            RequestBox.Clear();
            AlternativeArea.Visibility = Visibility.Collapsed;
            AlternativeBox.Clear();
        }

        private void OnIntentEdited(object sender, RoutedEventArgs e)
        {
            if (CopyButton == null) return;
            if (request != null || approvedPrompt != null) DraftStatus.Text = "回复意图已更新，请重新预览发送内容。";
            InterruptAutomaticTurn();
            InvalidatePrompt();
            UpdateActions();
        }

        private void OnFieldChanged(object sender, RoutedEventArgs e) => UpdateActions();
        private void OnDraftEdited(object sender, RoutedEventArgs e)
        {
            ++draftEdits;
            if (request == null && tracking && !autoNeedsBaseline && AutoDraftCheck.IsChecked == true)
                autoDraft.Bind(sourceKey, snapshot); // Typing resolves a waiting burst; an already dispatched suggestion can still be shown separately.
            UpdateActions();
        }

        private void OnPreparePrompt(object sender, RoutedEventArgs e)
        {
            if (history == null) return;
            try
            {
                InterruptAutomaticTurn();
                InvalidatePrompt();
                approvedPrompt = BuildCurrentPrompt();
                RenderHistory();
                RequestLabel.Text = "将发送到 OpenAI 的材料 · " + title;
                RequestBox.Text = approvedPrompt;
                RequestArea.Visibility = Visibility.Visible;
                DraftStatus.Text = "请核对上方材料。确认后只起草一次。";
            }
            catch (Exception ex) { DraftStatus.Text = ex.Message; }
            UpdateActions();
        }

        private async void OnGenerate(object sender, RoutedEventArgs e)
        {
            if (history == null || request != null || string.IsNullOrEmpty(approvedPrompt)) return;
            await GenerateAsync(approvedPrompt, false);
        }

        private async Task GenerateAsync(string payload, bool automatic)
        {
            int generation = targetVersion; int edits = draftEdits;
            long revision = snapshot.Revision;
            var cancellation = new CancellationTokenSource();
            try
            {
                if (BuildCurrentPrompt() != payload || revision != snapshot.Revision) { RenderHistory(); ContextChanged(); return; }
                approvedPrompt = null;
                request = cancellation;
                automaticRequest = automatic;
                UpdateActions();
                DraftStatus.Text = automatic ? "正在为这一轮来信自动备稿…" : "正在生成回复建议…";
                using (SecureString key = KeyBox.SecurePassword)
                {
                    var decision = await drafts.EvaluateAsync(payload, key, cancellation.Token);
                    if (generation != targetVersion || request != cancellation || cancellation.IsCancellationRequested ||
                        (automatic && !autoDraft.IsCurrent(sourceKey, revision))) return;
                    if (BuildCurrentPrompt() != payload || revision != snapshot.Revision) { RenderHistory(); ContextChanged(); return; }
                    RequestArea.Visibility = Visibility.Collapsed;
                    RequestBox.Clear();
                    if (decision.Kind != DraftDecisionKind.Reply)
                    {
                        DraftStatus.Text = (decision.Kind == DraftDecisionKind.Clarify ? "需要你确认：" : "本轮可不回：") + decision.Text +
                            (string.IsNullOrWhiteSpace(DraftBox.Text) ? "" : "（已有草稿已保留。）");
                        return;
                    }
                    string result = decision.Text;
                    if (edits != draftEdits || !string.IsNullOrWhiteSpace(DraftBox.Text))
                    {
                        AlternativeBox.Text = result;
                        AlternativeArea.Visibility = Visibility.Visible;
                        DraftStatus.Text = "当前草稿已保留，新建议可手动采用。";
                    }
                    else { DraftBox.Text = result; DraftStatus.Text = automatic ? "自动草稿已就绪，可修改和复制。" : "建议已生成。可修改和复制，再由你决定是否发送。"; }
                }
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
            catch (Exception ex)
            {
                if (generation == targetVersion && !cancellation.IsCancellationRequested) DraftStatus.Text = ex.Message;
            }
            finally
            {
                if (request == cancellation) { request = null; automaticRequest = false; }
                cancellation.Dispose();
                UpdateActions();
            }
        }

        private void OnAdopt(object sender, RoutedEventArgs e)
        {
            DraftBox.Text = AlternativeBox.Text;
            AlternativeBox.Clear();
            AlternativeArea.Visibility = Visibility.Collapsed;
        }
        private void OnCopy(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(DraftBox.Text)) return;
            try { Clipboard.SetText(DraftBox.Text); DraftStatus.Text = "草稿已复制。"; }
            catch (System.Runtime.InteropServices.ExternalException) { DraftStatus.Text = "剪贴板暂时不可用。"; }
        }

        private void UpdateActions()
        {
            if (CopyButton == null) return;
            bool bound = history != null;
            bool ready = bound && extracting == null;
            AutoDraftCheck.IsEnabled = ready && tracking && !string.IsNullOrEmpty(sourceKey);
            PreviewButton.IsEnabled = ready && !tracking && !awaitingPreview && preview == null;
            PauseButton.IsEnabled = tracking || awaitingPreview || preview != null;
            AddManualButton.IsEnabled = ready && !string.IsNullOrWhiteSpace(ManualBox.Text);
            DeleteButton.IsEnabled = ready;
            PrepareButton.IsEnabled = ready && HistoryBox.Text.Length > 0 && request == null;
            GenerateButton.IsEnabled = ready && approvedPrompt != null && request == null;
            CopyButton.IsEnabled = !string.IsNullOrWhiteSpace(DraftBox.Text);
            UpdateExportActions();
        }

        private void OpenHistory(string chosen, bool own)
        {
            string folder = Path.Combine(storeRoot, "ConversationAssistant", profile.Id.ToString("N"), own ? "Self" : "FileTransfer");
            history = new ConversationHistory(folder);
            snapshot = history.Read(chosen);
            startManualSegment = true;
        }

        private void SaveVisible(IReadOnlyList<ConversationLine> lines, long revision)
        {
            var current = history.Merge(title, lines, revision);
            if (current.Revision == snapshot.Revision) return;
            snapshot = current;
            RenderHistory();
            ContextChanged();
        }

        private void AppendManual(string text, int direction)
        {
            var sender = direction == 1 ? MessageDirection.Outgoing : direction == 2 ? MessageDirection.Incoming : MessageDirection.Unknown;
            if (startManualSegment && snapshot.Lines.Count > 0)
                snapshot = history.BeginSegment(title, Array.Empty<ConversationLine>(), snapshot.Revision);
            snapshot = history.AppendManual(title, new[] { new ConversationLine(sender, text) }, snapshot.Revision);
            startManualSegment = false;
        }

        private void DeleteHistory() => history.Delete(title, snapshot.Revision);

        private string BuildCurrentPrompt()
        {
            snapshot = history.Read(title);
            return ConversationDraftService.BuildPrompt(snapshot.ContextLines, snapshot.HasGap, IntentBox.Text);
        }

        private static string FormatLines(IEnumerable<ConversationLine> lines) => string.Join(Environment.NewLine, lines.Select(line =>
            (line.GapBefore ? "〔记录有间断〕" + Environment.NewLine : "") +
            (line.Direction == MessageDirection.Incoming ? "对方" : line.Direction == MessageDirection.Outgoing ? "本人" : "方向未知") +
            " · " + line.Text));

        private void RenderHistory()
        {
            int count = snapshot.Lines.Count;
            HistoryLabel.Text = "本机记录 · " + title + (count > 30 ? "（最近 30 / " + count + " 条）" : "（" + count + " 条）")
                + (snapshot.HasGap ? " · 记录有间断" : "");
            HistoryBox.Text = FormatLines(snapshot.Lines.Skip(Math.Max(0, count - 30)));
            HistoryBox.ScrollToEnd();
        }
    }
}
