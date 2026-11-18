// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using AppShield.Conversation;
using AppShield.Model;
using Microsoft.Win32;

namespace AppShield.UI
{
    public partial class ConversationPanel
    {
        private readonly DispatcherTimer identifyTimer;
        private readonly Func<AppProfile, CancellationToken, DiscoveredConversation> findConversation;
        private readonly Func<AppProfile, DiscoveredConversation, CancellationToken, VisibleConversationSample> readConversation;
        private readonly Action<string> copyExport;
        private readonly Func<string> chooseExportPath;
        private CancellationTokenSource identifying, extracting;
        private string exportTitle, lastAutoSource, lastAutoTitle;
        private int exportRevision;

        private void ResetExtraction()
        {
            identifyTimer.Stop();
            lastAutoSource = lastAutoTitle = null;
            identifying?.Cancel();
            extracting?.Cancel();
            if (IdentifyCurrentCheck == null) return;
            IdentifyCurrentCheck.IsChecked = false;
            IdentifyStatus.Text = "";
            ExtractStatus.Text = "";
            ClearExportPreview();
        }

        private void ClearExportPreview()
        {
            ++exportRevision;
            exportTitle = null;
            TranscriptBox.Clear();
            TranscriptLabel.Text = "";
            ExtractStatus.Text = "";
            TranscriptArea.Visibility = Visibility.Collapsed;
            UpdateExportActions();
        }

        private void OnIdentifyChanged(object sender, RoutedEventArgs e)
        {
            if (IdentifyStatus == null || identifyTimer == null) return;
            if (IdentifyCurrentCheck.IsChecked == true && profile != null && IsVisible)
            {
                EnterLocalOnly();
                lastAutoSource = lastAutoTitle = null;
                IdentifyStatus.Text = "等待切到微信单聊，自动预览保留在本页。";
                UpdateActions();
                identifyTimer.Start();
                OnIdentifyTick(null, EventArgs.Empty);
            }
            else
            {
                identifyTimer.Stop();
                identifying?.Cancel();
                lastAutoSource = lastAutoTitle = null;
                IdentifyStatus.Text = "";
            }
        }

        private async void OnIdentifyTick(object sender, EventArgs e)
        {
            if (identifying != null || extracting != null || sampling || tracking || awaitingPreview ||
                profile == null || !IsVisible || IdentifyCurrentCheck.IsChecked != true) return;
            var current = profile;
            using (var op = new CancellationTokenSource())
            {
                identifying = op;
                try
                {
                    var found = await Task.Run(() => findConversation(current, op.Token));
                    if (op.IsCancellationRequested || !IsVisible || profile != current) return;
                    if (found.State != VisibleConversationState.Verified || string.IsNullOrEmpty(found.SourceKey) ||
                        ConversationSettings.IsExcludedTitle(found.Title))
                    {
                        lastAutoSource = lastAutoTitle = null;
                        IdentifyStatus.Text = found.Hint;
                        if (found.State != VisibleConversationState.NotForeground) ClearExportPreview();
                        return;
                    }
                    if (lastAutoSource == found.SourceKey && lastAutoTitle == found.Title) return;
                    ClearExportPreview();
                    lastAutoSource = found.SourceKey;
                    lastAutoTitle = found.Title;
                    var frame = await Task.Run(() => readConversation(current, found, op.Token));
                    if (op.IsCancellationRequested || !IsVisible || profile != current) return;
                    if (!PreviewExtracted(found, frame))
                    {
                        ClearExportPreview();
                        IdentifyStatus.Text = "当前对话的可见文字暂时无法核实，可手动重试。";
                    }
                    else IdentifyStatus.Text = "已自动预览 · " + found.Title;
                }
                catch (OperationCanceledException) when (op.IsCancellationRequested) { }
                catch (Exception)
                {
                    if (!op.IsCancellationRequested)
                    {
                        lastAutoSource = lastAutoTitle = null;
                        ClearExportPreview();
                        IdentifyStatus.Text = "当前对话暂时无法核实。";
                    }
                }
                finally { if (identifying == op) identifying = null; }
            }
        }

        private async void OnExtractCurrent(object sender, RoutedEventArgs e)
        {
            if (profile == null || extracting != null || !IsVisible) return;
            identifying?.Cancel();
            EnterLocalOnly();
            ClearExportPreview();
            var current = profile;
            using (var op = new CancellationTokenSource())
            {
                extracting = op;
                UpdateActions();
                ExtractStatus.Text = "正在查找当前对话。普通微信窗口可切回一次，识别后会自动提取。";
                var watch = Stopwatch.StartNew();
                try
                {
                    while (watch.Elapsed < TimeSpan.FromSeconds(25))
                    {
                        op.Token.ThrowIfCancellationRequested();
                        var found = await Task.Run(() => findConversation(current, op.Token));
                        op.Token.ThrowIfCancellationRequested();
                        if (!IsVisible || current != profile) return;
                        if (found.State == VisibleConversationState.NotForeground)
                        {
                            await Task.Delay(650, op.Token);
                            continue;
                        }
                        if (found.State != VisibleConversationState.Verified || string.IsNullOrEmpty(found.SourceKey) ||
                            ConversationSettings.IsExcludedTitle(found.Title))
                        { ExtractStatus.Text = found.Hint; return; }
                        var frame = await Task.Run(() => readConversation(current, found, op.Token));
                        op.Token.ThrowIfCancellationRequested();
                        if (!IsVisible || current != profile) return;
                        if (!PreviewExtracted(found, frame)) ExtractStatus.Text = "对话已切换或没有可核实的可见文字，请重新提取。";
                        else { lastAutoSource = found.SourceKey; lastAutoTitle = found.Title; }
                        return;
                    }
                    ExtractStatus.Text = "等待已结束。打开目标微信对话后可重新提取。";
                }
                catch (OperationCanceledException) when (op.IsCancellationRequested) { }
                catch (Exception ex) { if (!op.IsCancellationRequested) ExtractStatus.Text = ex.Message; }
                finally { if (extracting == op) extracting = null; UpdateActions(); }
            }
        }

        private bool PreviewExtracted(DiscoveredConversation found, VisibleConversationSample frame)
        {
            if (frame.State != VisibleConversationState.Verified || frame.SourceKey != found.SourceKey || frame.Title != found.Title ||
                ConversationSettings.IsExcludedTitle(found.Title) || frame.Lines.Length == 0) return false;
            ShowExportPreview(found.Title, "当前可见消息", ConversationTranscript.Format(found.Title, frame.Lines));
            ExtractStatus.Text = "已提取 " + frame.Lines.Length + " 条可见文字消息。";
            return true;
        }

        private void OnCancelExtract(object sender, RoutedEventArgs e)
        {
            extracting?.Cancel();
            ExtractStatus.Text = "已取消本次提取。";
        }

        private void OnExportHistory(object sender, RoutedEventArgs e)
        {
            if (history == null || ConversationSettings.IsExcludedTitle(title)) return;
            try
            {
                TakeLocalPreviewControl();
                var saved = history.Read(title);
                if (saved.Lines.Count == 0) { ExtractStatus.Text = "本机没有此对话的记录。"; return; }
                ShowExportPreview(title, "全部本机记录", ConversationTranscript.Format(title, saved.Lines, true));
                ExtractStatus.Text = "已载入 " + saved.Lines.Count + " 条本机记录供导出。";
            }
            catch (Exception ex) { ExtractStatus.Text = ex.Message; }
        }

        private void OnExportHistorySelection(object sender, RoutedEventArgs e)
        {
            if (history == null || ConversationSettings.IsExcludedTitle(title) || string.IsNullOrWhiteSpace(HistoryBox.SelectedText)) return;
            try
            {
                TakeLocalPreviewControl();
                ShowExportPreview(title, "本机记录选段", ConversationTranscript.FormatSelection(title, HistoryBox.SelectedText));
                ExtractStatus.Text = "预览现仅包含选中的历史片段。";
            }
            catch (Exception ex) { ExtractStatus.Text = ex.Message; }
        }

        private void ShowExportPreview(string target, string scope, string text)
        {
            ++exportRevision;
            exportTitle = target;
            TranscriptLabel.Text = target + " · " + scope;
            TranscriptBox.Text = text;
            TranscriptArea.Visibility = Visibility.Visible;
            TranscriptBox.ScrollToHome();
            TranscriptLabel.BringIntoView();
            UpdateExportActions();
        }

        private void OnClearTranscript(object sender, RoutedEventArgs e)
        {
            TakeLocalPreviewControl();
            ExtractStatus.Text = "预览已清空。";
        }

        private void TakeLocalPreviewControl()
        {
            IdentifyCurrentCheck.IsChecked = false;
            identifying?.Cancel();
            extracting?.Cancel();
            EnterLocalOnly();
            ClearExportPreview();
            UpdateActions();
        }

        private void EnterLocalOnly()
        {
            bool wasTracking = tracking || awaitingPreview || preview != null;
            bool wasPreparing = request != null || approvedPrompt != null;
            StopCapture();
            InvalidatePrompt();
            if (wasTracking) CaptureStatus.Text = "本次本地导出已暂停原来的跟踪。";
            if (wasPreparing) DraftStatus.Text = "先前的草稿请求或预览已取消。";
        }

        private void OnTranscriptSelection(object sender, RoutedEventArgs e) => UpdateExportActions();

        private void UpdateExportActions()
        {
            if (ExportHistorySelectionButton == null || SaveTranscriptButton == null) return;
            bool busy = extracting != null;
            ExtractCurrentButton.IsEnabled = profile?.IsWeChat == true && !busy;
            CancelExtractButton.Visibility = busy ? Visibility.Visible : Visibility.Collapsed;
            ExportHistoryButton.IsEnabled = history != null && snapshot?.Lines.Count > 0;
            ExportHistorySelectionButton.IsEnabled = ExportHistoryButton.IsEnabled && !string.IsNullOrWhiteSpace(HistoryBox.SelectedText);
            bool selected = TranscriptBox.SelectionLength > 0;
            CopyTranscriptButton.Content = selected ? "复制选段" : "复制全文";
            SaveTranscriptButton.Content = selected ? "另存选段…" : "另存文本…";
            CopyTranscriptButton.IsEnabled = SaveTranscriptButton.IsEnabled = exportTitle != null && TranscriptBox.Text.Length > 0;
        }

        private string ChosenExportText()
        {
            if (exportTitle == null || ConversationSettings.IsExcludedTitle(exportTitle))
            { ClearExportPreview(); throw new InvalidOperationException("当前预览不可导出。"); }
            return TranscriptBox.SelectionLength == 0 ? TranscriptBox.Text : TranscriptBox.SelectedText;
        }

        private void OnCopyTranscript(object sender, RoutedEventArgs e)
        {
            try { copyExport(ChosenExportText()); ExtractStatus.Text = "文本已复制到剪贴板。"; }
            catch (Exception ex) { ExtractStatus.Text = "复制未完成。" + ex.Message; }
        }

        private void OnTranscriptCommand(object sender, ExecutedRoutedEventArgs e)
        {
            if (e.Command != ApplicationCommands.Copy) return;
            e.Handled = true;
            if (TranscriptBox.SelectionLength > 0) OnCopyTranscript(sender,e);
        }

        private string PickExportPath()
        {
            var picker = new SaveFileDialog { Title = "保存对话文本", FileName = "对话摘录-" + DateTime.Now.ToString("yyyyMMdd-HHmm"),
                DefaultExt = ".txt", AddExtension = true, Filter = "文本文件 (*.txt)|*.txt|Markdown 文件 (*.md)|*.md", OverwritePrompt = false };
            return picker.ShowDialog(Window.GetWindow(this)) == true ? picker.FileName : null;
        }

        private void OnSaveTranscript(object sender, RoutedEventArgs e)
        {
            try
            {
                string approvedTarget = exportTitle;
                int approvedVersion = exportRevision;
                string text = ChosenExportText();
                string path = chooseExportPath();
                if (string.IsNullOrEmpty(path)) return;
                bool overwrite = File.Exists(path);
                if (overwrite && MessageBox.Show(Window.GetWindow(this), "覆盖已有文件？\n" + path, "保存对话文本",
                        MessageBoxButton.YesNo, MessageBoxImage.Question, MessageBoxResult.No) != MessageBoxResult.Yes) return;
                if (exportRevision != approvedVersion || exportTitle != approvedTarget || ChosenExportText() != text)
                    throw new InvalidOperationException("文本预览已更改，请重新核对后保存。");
                ConversationTranscript.Save(path, text, overwrite);
                ExtractStatus.Text = "对话文本已保存。";
            }
            catch (Exception ex) { ExtractStatus.Text = "保存未完成。" + ex.Message; }
        }
    }
}
