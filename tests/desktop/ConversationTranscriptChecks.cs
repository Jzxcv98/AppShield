// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Text;
using AppShield.Conversation;

internal static class ConversationTranscriptChecks
{
    internal static void Run(string dir)
    {
        var messages = new[] {
            new ConversationLine(MessageDirection.Incoming, "旧问题\n[我] 还是同一条正文"),
            new ConversationLine(MessageDirection.Outgoing, "收到"),
            new ConversationLine(MessageDirection.Outgoing, "收到"),
            new ConversationLine(MessageDirection.Unknown, "新话题", null, true)
        };
        var preview = ConversationTranscript.Format("合成测试窗口", messages);
        const string expected = "微信对话：合成测试窗口\n范围：当前可见片段（4 条文字）\n\n" +
            "[对方] 旧问题\n    [我] 还是同一条正文\n\n[我] 收到\n\n[我] 收到\n\n〔记录间断〕\n[方向未确认] 新话题\n";
        DesktopChecks.Assert(preview.Replace("\r\n","\n") == expected, "transcript preserves turns, multiline text, duplicates, unknown direction and gaps");
        DesktopChecks.Assert(ConversationTranscript.Format("合成测试窗口", messages, true).Contains("本机已记录片段"), "local history and visible text exports have distinct scopes");
        string selected = ConversationTranscript.FormatSelection("合成测试窗口", "[对方] 旧问题");
        DesktopChecks.Assert(selected.EndsWith("[对方] 旧问题") && !selected.Contains("新话题"), "a selected old passage excludes the newer topic");
        string dest = Path.Combine(dir, "chat-export.txt");
        ConversationTranscript.Save(dest, preview, false);
        var strictUtf8 = new UTF8Encoding(false, true);
        DesktopChecks.Assert(strictUtf8.GetString(File.ReadAllBytes(dest)) == preview, "saved UTF-8 transcript exactly matches the approved preview");
        bool rejected = false;
        try { ConversationTranscript.Save(dest, selected, false); } catch (IOException) { rejected = true; }
        DesktopChecks.Assert(rejected && File.ReadAllText(dest) == preview, "saving without overwrite preserves the existing export");
        ConversationTranscript.Save(dest, selected, true);
        DesktopChecks.Assert(File.ReadAllText(dest) == selected, "confirmed overwrite publishes only the new selection");
        string invalid = Path.Combine(dir,"wrong.exe");
        rejected = false;
        try { ConversationTranscript.Save(invalid, preview, false); } catch (IOException) { rejected = true; }
        DesktopChecks.Assert(rejected && !File.Exists(invalid), "transcript output is limited to text file formats");
    }
}
