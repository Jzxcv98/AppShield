// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace AppShield.Telegram
{
    internal sealed class StartupEvidence
    {
        private readonly Dictionary<string, Tuple<long, DateTime>> before = new Dictionary<string, Tuple<long, DateTime>>();
        internal StartupEvidence(string work)
        {
            for (int i = -1; i < 10; i++)
            {
                var path = Path.Combine(work, i < 0 ? "log.txt" : "log_start" + i + ".txt");
                var f = new FileInfo(path);
                before[path] = f.Exists ? Tuple.Create(f.Length, f.LastWriteTimeUtc) : null;
            }
        }
        internal string FailureStage()
        {
            bool listen = false, reply = false;
            foreach (var item in before)
            {
                try
                {
                    var f = new FileInfo(item.Key);
                    if (!f.Exists || (item.Value != null && f.LastWriteTimeUtc == item.Value.Item2 && f.Length == item.Value.Item1)) continue;
                    using (var input = SafeFiles.OpenRead(item.Key, true))
                    {
                        // Only inspect this attempt's bounded suffix. Stored account data and
                        // earlier append-only log entries are outside this diagnostic.
                        long offset = item.Value != null && input.Length > item.Value.Item1 ? item.Value.Item1 : 0;
                        input.Position = Math.Max(offset, input.Length - 131072);
                        var buf = new byte[131072]; int n = input.Read(buf, 0, buf.Length);
                        foreach (var line in Encoding.UTF8.GetString(buf, 0, n).Split('\n'))
                        {
                            int timestamp = line.IndexOf("] ", StringComparison.Ordinal);
                            if (timestamp < 1 || timestamp > 32 || line.TrimStart('\uFEFF').StartsWith("[", StringComparison.Ordinal) == false) continue;
                            var message = line.Substring(timestamp + 2);
                            if (message.StartsWith("Failed to start listening to ", StringComparison.Ordinal)) listen = true;
                            if (message.StartsWith("Show command response received,", StringComparison.Ordinal)) reply = true;
                        }
                    }
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
            if (listen && !reply) return "本轮 Telegram 启动日志确认本地 IPC 监听失败。";
            if (reply && !listen) return "本轮 Telegram 启动请求已转给已有实例。";
            return "本轮未取得足以定位阶段的启动标记。";
        }
    }
}
