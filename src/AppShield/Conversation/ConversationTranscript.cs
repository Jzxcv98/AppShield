// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AppShield.Conversation
{
    internal static class ConversationTranscript
    {
        internal static string Format(string target, IReadOnlyList<ConversationLine> lines) =>
            Format(target, lines, false);

        internal static string Format(string target, IReadOnlyList<ConversationLine> lines, bool fromLocalHistory)
        {
            CheckTarget(target);
            if (lines == null || lines.Count == 0) throw new InvalidOperationException("没有可导出的消息。");
            var result = new StringBuilder();
            result.Append("微信对话：").AppendLine(target);
            result.Append("范围：").Append(fromLocalHistory ? "本机已记录片段" : "当前可见片段")
                .Append("（").Append(lines.Count).AppendLine(" 条文字）");
            foreach (var line in lines)
            {
                if (line == null) throw new InvalidDataException("消息记录不完整。");
                result.AppendLine();
                if (line.GapBefore) result.AppendLine("〔记录间断〕");
                string speaker = line.Direction == MessageDirection.Incoming ? "对方" :
                    line.Direction == MessageDirection.Outgoing ? "我" : "方向未确认";
                // Indentation keeps line breaks in a bubble from looking like extra turns.
                result.Append("[").Append(speaker).Append("] ").AppendLine(
                    line.Text.Replace("\r\n", "\n").Replace('\r', '\n').Replace("\n", Environment.NewLine + "    "));
            }
            return result.ToString();
        }

        internal static string FormatSelection(string target, string selection)
        {
            CheckTarget(target);
            if (string.IsNullOrWhiteSpace(selection)) throw new InvalidOperationException("请先选择要导出的文字。");
            return "微信对话：" + target + Environment.NewLine + "范围：手动选择的对话片段" +
                Environment.NewLine + Environment.NewLine + selection;
        }

        private static void CheckTarget(string target)
        {
            if (!WeChatVisibleConversation.IsAllowedTitle(target, true))
                throw new InvalidOperationException("此对话不能导出。");
        }

        internal static void Save(string destination, string approvedText, bool overwrite)
        {
            destination = SafeFiles.LocalPath(destination);
            var extension = Path.GetExtension(destination);
            if (!string.Equals(extension, ".txt", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(extension, ".md", StringComparison.OrdinalIgnoreCase))
                throw new IOException("请选择 .txt 或 .md 文件。");
            TransferBroker.SavePlainText(destination, approvedText, overwrite);
        }
    }
}
