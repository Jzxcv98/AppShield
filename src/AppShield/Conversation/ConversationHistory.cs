// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace AppShield.Conversation
{
    internal enum MessageDirection { Unknown, Incoming, Outgoing }

    internal sealed class ConversationLine
    {
        internal MessageDirection Direction { get; }
        internal string Text { get; }
        // Only a durable source message identifier belongs here. Screen coordinates and UIA
        // runtime IDs can change or be reused when a message list is scrolled.
        internal string StableId { get; }
        internal bool GapBefore { get; }

        internal ConversationLine(MessageDirection direction, string text, string stableId = null)
            : this(direction, text, stableId, false) { }

        internal ConversationLine(MessageDirection direction, string text, string stableId, bool gap)
        {
            if (direction < MessageDirection.Unknown || direction > MessageDirection.Outgoing ||
                string.IsNullOrWhiteSpace(text) || text.Length > 16384 || text.IndexOf('\0') >= 0 ||
                (stableId != null && (stableId.Length == 0 || stableId.Length > 512 || stableId.Any(char.IsControl))))
                throw new ArgumentException("消息的内容、长度或方向无效。");
            Direction = direction;
            Text = text;
            StableId = stableId;
            GapBefore = gap;
        }
    }

    internal sealed class ConversationSnapshot
    {
        internal long Revision { get; }
        internal IReadOnlyList<ConversationLine> Lines { get; }
        internal IReadOnlyList<ConversationLine> ContextLines { get; }
        internal bool HasGap { get; }
        // A live sample may certify a unique append to a prior revision. Loading stored
        // history, adding manual input, or observing ambiguous overlap never grants it.
        internal long? ConfirmedAppendFrom { get; }

        internal ConversationSnapshot(long revision, List<ConversationLine> lines, bool awaitingFrame,
            long? confirmedAppendFrom = null)
        {
            Revision = revision;
            ConfirmedAppendFrom = confirmedAppendFrom;
            Lines = Array.AsReadOnly(lines.ToArray());
            int gap = lines.FindLastIndex(line => line.GapBefore);
            HasGap = gap >= 0 || (awaitingFrame && lines.Count > 0);
            ContextLines = awaitingFrame ? Array.AsReadOnly(new ConversationLine[0]) :
                gap < 0 ? Lines : Array.AsReadOnly(lines.Skip(gap).ToArray());
        }
    }

    internal sealed class ConversationHistory
    {
        private const int MaxLines = 256, MaxCharacters = 128 * 1024;
        private const int MaxSampleLines = 128, MaxSampleCharacters = 64 * 1024;
        private const int MaxStoreBytes = 8 * 1024 * 1024;
        private static readonly UTF8Encoding Utf8 = new UTF8Encoding(false, true);
        private static readonly byte[] Entropy = Utf8.GetBytes("AppShield conversation history v1");
        private readonly string folder, file;

        private sealed class Chat
        {
            internal long Revision;
            internal int FrameCount;
            internal bool AwaitingFrame;
            internal long? ConfirmedAppendFrom; // Transient evidence from this individual Merge.
            internal readonly List<ConversationLine> Rows = new List<ConversationLine>();
        }

        private sealed class Store
        {
            internal long Generation;
            internal readonly Dictionary<string, Chat> Chats = new Dictionary<string, Chat>(StringComparer.Ordinal);
        }

        internal ConversationHistory(string root)
        {
            folder = Path.Combine(SafeFiles.LocalPath(root), "ConversationHistory");
            file = Path.Combine(folder, "history.bin");
        }

        internal ConversationSnapshot Read(string target) => Access(target, null, chat => false);

        // Explicit confirmation starts a new context even if a different window/account used the same title.
        internal ConversationSnapshot BeginSegment(string target, IReadOnlyList<ConversationLine> visible, long? expectedRevision = null)
        {
            var sample = ValidateSample(visible);
            return Access(target, expectedRevision, chat =>
            {
                if (sample.Length > 0) return Append(chat, sample, 0, chat.Rows.Count != 0);
                if (chat.Rows.Count == 0 || chat.AwaitingFrame) return false;
                chat.FrameCount = 0;
                chat.AwaitingFrame = true;
                return true;
            });
        }

        internal ConversationSnapshot Merge(string target, IReadOnlyList<ConversationLine> visible, long? expectedRevision = null)
        {
            var sample = ValidateSample(visible);
            return Access(target, expectedRevision, chat =>
            {
                if (sample.Length == 0) return false;
                int first = chat.Rows.Count - chat.FrameCount;
                if (chat.FrameCount == 0) return Append(chat, sample, 0, chat.Rows.Count != 0);

                // A repeated scan or temporarily smaller viewport hasn't
                // established any new chronological rows. Retain the last forward anchor.
                for (int i = first; i + sample.Length <= chat.Rows.Count; i++)
                    if (EqualRange(chat.Rows, i, sample, 0, sample.Length)) return false;
                // When durable source IDs are available, scrolling back to previously
                // observed messages must neither replay them nor move the live anchor.
                if (sample.All(line => line.StableId != null))
                {
                    for (int i = 0; i < first && i + sample.Length <= chat.Rows.Count; i++)
                        if (EqualRange(chat.Rows, i, sample, 0, sample.Length)) return false;
                    for (int count = 1; count < sample.Length && count < chat.FrameCount; count++)
                        if (EqualRange(chat.Rows, first, sample, sample.Length - count, count)) return false;
                }

                // An expanded viewport may show older rows before the whole previous frame.
                // Accept its tail only if the old frame occurs exactly once in the sample.
                int embedded = -1;
                bool ambiguous = false;
                for (int i = 1; i + chat.FrameCount <= sample.Length; i++)
                {
                    if (!EqualRange(chat.Rows, first, sample, i, chat.FrameCount)) continue;
                    if (embedded >= 0 || EqualRange(chat.Rows, first, sample, 0, chat.FrameCount))
                        ambiguous = true;
                    embedded = i;
                }
                if (embedded >= 0 && !ambiguous)
                {
                    int tail = embedded + chat.FrameCount;
                    if (tail == sample.Length) return false;
                    chat.ConfirmedAppendFrom = chat.Revision;
                    return Append(chat, sample, tail, false, chat.FrameCount);
                }

                int overlap = 0;
                for (int count = 1; count <= Math.Min(chat.FrameCount, sample.Length); count++)
                {
                    if (!EqualRange(chat.Rows, chat.Rows.Count - count, sample, 0, count)) continue;
                    if (overlap != 0) ambiguous = true;
                    overlap = count;
                }
                // Multiple alignments imply an unknown number of old rows. Keep the entire
                // latest frame as a separate GPT context, sharing its longest observed prefix
                // with local history rather than manufacturing extra copies of the messages.
                if (overlap > 0 && ambiguous)
                {
                    int boundary = chat.Rows.Count - overlap;
                    var row = chat.Rows[boundary];
                    chat.Rows[boundary] = new ConversationLine(row.Direction, row.Text, row.StableId, true);
                }
                if (overlap > 0 && !ambiguous) chat.ConfirmedAppendFrom = chat.Revision;
                return Append(chat, sample, overlap, overlap == 0, overlap);
            });
        }

        // Consecutive manual entries belong to one user-selected excerpt. Crossing between
        // manual entry and automatic capture starts a new context in either direction.
        internal ConversationSnapshot AppendManual(string target, IReadOnlyList<ConversationLine> lines, long? expectedRevision = null)
        {
            var sample = ValidateSample(lines);
            return Access(target, expectedRevision, chat =>
            {
                if (sample.Length == 0) return false;
                Append(chat, sample, 0, chat.Rows.Count != 0 && (chat.AwaitingFrame || chat.FrameCount != 0));
                chat.FrameCount = 0;
                return true;
            });
        }

        internal ConversationSnapshot Delete(string target, long? expectedRevision = null) =>
            Access(target, expectedRevision, c => { c.Rows.Clear(); c.FrameCount = 0; c.AwaitingFrame = false; return true; });

        private static ConversationLine[] ValidateSample(IReadOnlyList<ConversationLine> lines)
        {
            if (lines == null || lines.Count > MaxSampleLines) throw new ArgumentException("单次最多处理 128 条消息。");
            var sample = lines.ToArray();
            if (sample.Any(line => line == null) || sample.Sum(line => line.Text.Length) > MaxSampleCharacters)
                throw new ArgumentException("单次消息内容过长或含空行对象。");
            var ids = sample.Where(line => line.StableId != null).Select(line => line.StableId).ToArray();
            if (ids.Distinct(StringComparer.Ordinal).Count() != ids.Length)
                throw new ArgumentException("同一帧的消息标识重复，无法核实消息顺序。");
            return sample;
        }

        private static bool EqualRange(IReadOnlyList<ConversationLine> left, int a,
            IReadOnlyList<ConversationLine> right, int b, int count)
        {
            for (int i = 0; i < count; i++)
            {
                var x = left[a + i]; var y = right[b + i];
                if (x.Direction != y.Direction || x.Text != y.Text || x.StableId != y.StableId) return false;
            }
            return true;
        }

        private static bool Append(Chat chat, ConversationLine[] sample, int start, bool gap, int anchor = 0)
        {
            chat.AwaitingFrame = false;
            for (int i = start; i < sample.Length; i++)
            {
                var value = sample[i];
                chat.Rows.Add(new ConversationLine(value.Direction, value.Text, value.StableId, gap && i == start));
            }
            chat.FrameCount = anchor + sample.Length - start;
            int characters = chat.Rows.Sum(line => line.Text.Length);
            int drop = 0;
            while (chat.Rows.Count - drop > MaxLines || characters > MaxCharacters)
                characters -= chat.Rows[drop++].Text.Length;
            if (drop != 0)
            {
                chat.ConfirmedAppendFrom = null;
                chat.Rows.RemoveRange(0, drop);
                var first = chat.Rows[0];
                chat.Rows[0] = new ConversationLine(first.Direction, first.Text, first.StableId, true);
                chat.FrameCount = Math.Min(chat.FrameCount, chat.Rows.Count);
            }
            return true;
        }

        private ConversationSnapshot Access(string target, long? expected, Func<Chat, bool> change)
        {
            if (string.IsNullOrWhiteSpace(target) || target.Length > 160 || target.Any(char.IsControl) ||
                ConversationSettings.IsExcludedTitle(target))
                throw new ArgumentException("请选择允许记录的测试对话。");
            using (SafeFiles.PinDirectory(folder, true))
            using (Lock())
            {
                // No other writer can own this staging file while we hold the OS file lock.
                // Recover after termination so a later deletion also clears an abandoned encrypted copy.
                if (File.Exists(file + ".pending")) File.Delete(file + ".pending");
                var store = Load();
                if (!store.Chats.TryGetValue(target, out var chat)) chat = new Chat { Revision = store.Generation };
                if (expected.HasValue && expected.Value != chat.Revision)
                    throw new InvalidOperationException("记录已更改，请重新载入该对话。");
                if (change(chat))
                {
                    chat.Revision = store.Generation = checked(store.Generation + 1);
                    if (chat.Rows.Count == 0) store.Chats.Remove(target); else store.Chats[target] = chat;
                    Save(store);
                }
                return new ConversationSnapshot(chat.Revision, chat.Rows, chat.AwaitingFrame, chat.ConfirmedAppendFrom);
            }
        }

        private FileStream Lock()
        {
            var elapsed = Stopwatch.StartNew();
            while (true)
            {
                try { return new FileStream(Path.Combine(folder, "history.lock"), FileMode.OpenOrCreate,
                    FileAccess.ReadWrite, FileShare.None); }
                catch (IOException ex) when (((ex.HResult & 65535) == 32 || (ex.HResult & 65535) == 33) &&
                    elapsed.Elapsed < TimeSpan.FromSeconds(5))
                { Thread.Sleep(30); }
            }
        }

        private Store Load()
        {
            var store = new Store();
            if (!File.Exists(file)) return store;
            byte[] encrypted;
            using (var input = SafeFiles.OpenRead(file, true))
            {
                if (input.Length <= 0 || input.Length > MaxStoreBytes + 64 * 1024) throw new InvalidDataException("记录文件长度无效。");
                using (var reader = new BinaryReader(input)) encrypted = reader.ReadBytes((int)input.Length);
            }
            byte[] plain = ProtectedData.Unprotect(encrypted, Entropy, DataProtectionScope.CurrentUser);
            try
            {
                using (var stream = new MemoryStream(plain, false))
                using (var reader = new BinaryReader(stream, Utf8))
                {
                    int version = reader.ReadInt32();
                    if (plain.Length > MaxStoreBytes || (version != 1 && version != 2)) throw new InvalidDataException("记录格式无效。");
                    store.Generation = reader.ReadInt64();
                    int targets = reader.ReadInt32();
                    if (targets < 0 || targets > 128 || store.Generation < 0) throw new InvalidDataException("记录索引无效。");
                    for (int i = 0; i < targets; i++)
                    {
                        string title = reader.ReadString();
                        var chat = new Chat { Revision = reader.ReadInt64(), FrameCount = reader.ReadInt32() };
                        if (version == 2) chat.AwaitingFrame = reader.ReadBoolean();
                        int count = reader.ReadInt32();
                        if (count <= 0 || count > MaxLines || chat.FrameCount < 0 || chat.FrameCount > count ||
                            chat.Revision <= 0 || chat.Revision > store.Generation) throw new InvalidDataException("对话记录无效。");
                        for (int j = 0; j < count; j++)
                        {
                            var direction = (MessageDirection)reader.ReadByte();
                            string text = reader.ReadString(), id = reader.ReadString();
                            chat.Rows.Add(new ConversationLine(direction, text, id.Length == 0 ? null : id, reader.ReadBoolean()));
                        }
                        store.Chats.Add(title, chat);
                    }
                    if (stream.Position != stream.Length) throw new InvalidDataException("记录包含多余内容。");
                }
                return store;
            }
            finally { Array.Clear(plain, 0, plain.Length); }
        }

        private void Save(Store store)
        {
            if (store.Chats.Count > 128) throw new InvalidOperationException("对话数量已达本地上限。");
            byte[] encrypted;
            using (var output = new MemoryStream())
            using (var writer = new BinaryWriter(output, Utf8, true))
            {
                try
                {
                    writer.Write(2); writer.Write(store.Generation); writer.Write(store.Chats.Count);
                    foreach (var pair in store.Chats)
                    {
                        var chat = pair.Value;
                        writer.Write(pair.Key); writer.Write(chat.Revision); writer.Write(chat.FrameCount);
                        writer.Write(chat.AwaitingFrame); writer.Write(chat.Rows.Count);
                        foreach (var row in chat.Rows)
                        {
                            writer.Write((byte)row.Direction); writer.Write(row.Text); writer.Write(row.StableId ?? ""); writer.Write(row.GapBefore);
                        }
                    }
                    writer.Flush();
                    if (output.Length > MaxStoreBytes) throw new InvalidOperationException("本地记录已满，请删除不再需要的对话。");
                    byte[] plain = output.ToArray();
                    try { encrypted = ProtectedData.Protect(plain, Entropy, DataProtectionScope.CurrentUser); }
                    finally { Array.Clear(plain, 0, plain.Length); }
                }
                finally { Array.Clear(output.GetBuffer(), 0, (int)output.Length); }
            }
            string tmp = file + ".pending";
            try
            {
                using (var output = new FileStream(tmp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                { output.Write(encrypted, 0, encrypted.Length); output.Flush(true); }
                if (File.Exists(file)) File.Replace(tmp, file, null); else File.Move(tmp, file);
            }
            finally { if (File.Exists(tmp)) File.Delete(tmp); }
        }
    }
}
