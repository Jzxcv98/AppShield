// SPDX-License-Identifier: GPL-3.0-only
using System;

namespace AppShield.Conversation
{
    // A UI-thread state machine. The caller owns foreground validation, explicit cloud consent
    // and cancellation of any request already dispatched. No timers, data access, or I/O here.
    internal sealed class ConversationAutoDraftTrigger
    {
        internal static readonly TimeSpan QuietPeriod = TimeSpan.FromSeconds(10);
        private string binding;
        private ConversationSnapshot baseline;
        private DateTime? lastIncoming;
        private long? claimed;

        internal void Reset()
        {
            binding = null;
            baseline = null;
            lastIncoming = null;
            claimed = null;
        }

        internal void Bind(string bindingKey, ConversationSnapshot initial)
        {
            Reset();
            if (string.IsNullOrWhiteSpace(bindingKey) || initial == null) return;
            binding = bindingKey;
            baseline = initial;
        }

        // True means any previously claimed request must be cancelled or its late result discarded.
        internal bool Observe(string bindingKey, ConversationSnapshot previous, ConversationSnapshot current, DateTime utcNow)
        {
            if (baseline == null || bindingKey != binding || previous == null || current == null)
            {
                Reset();
                return true;
            }
            if (current.Revision < baseline.Revision)
            {
                // A late observation cannot rewind a confirmed baseline.
                Reset();
                return true;
            }
            if (previous.Revision != baseline.Revision || !SameRows(baseline, previous))
            {
                Bind(bindingKey, current);
                return true;
            }
            if (current.Revision == previous.Revision && SameRows(previous, current)) return false;

            bool reliable = IsIncomingAppend(previous, current);
            baseline = current;
            claimed = null;
            lastIncoming = reliable ? (DateTime?)utcNow : null;
            return true;
        }

        internal bool TryTake(string bindingKey, long currentRevision, DateTime utcNow)
        {
            if (baseline == null || bindingKey != binding || currentRevision != baseline.Revision)
            {
                Reset();
                return false;
            }
            if (!lastIncoming.HasValue || claimed.HasValue || utcNow - lastIncoming.Value < QuietPeriod) return false;
            lastIncoming = null;
            claimed = currentRevision; // A failed/cancelled API request is never automatically retried.
            return true;
        }

        internal bool IsCurrent(string bindingKey, long revision) =>
            baseline != null && binding == bindingKey && baseline.Revision == revision && claimed == revision;

        private static bool SameRows(ConversationSnapshot a, ConversationSnapshot b) =>
            a.Lines.Count == b.Lines.Count && a.ContextLines.Count == b.ContextLines.Count && HasPrefix(a, b);

        private static bool HasPrefix(ConversationSnapshot old, ConversationSnapshot next)
        {
            if (old.Lines.Count > next.Lines.Count) return false;
            for (int i = 0; i < old.Lines.Count; i++)
            {
                var a = old.Lines[i]; var b = next.Lines[i];
                if (a.Direction != b.Direction || a.Text != b.Text || a.StableId != b.StableId ||
                    a.GapBefore != b.GapBefore) return false;
            }
            return true;
        }

        private static bool IsIncomingAppend(ConversationSnapshot old, ConversationSnapshot next)
        {
            // A lazy first frame, truncated prefix, newly marked gap, or a rebind can
            // never be interpreted as live new messages. An older gap can stay in history.
            int added = next.Lines.Count - old.Lines.Count;
            if (next.ConfirmedAppendFrom != old.Revision || next.Revision <= old.Revision || old.ContextLines.Count == 0 || added <= 0 ||
                next.ContextLines.Count != old.ContextLines.Count + added || !HasPrefix(old, next))
                return false;
            for (int i = old.Lines.Count; i < next.Lines.Count; i++)
                if (next.Lines[i].GapBefore || next.Lines[i].Direction != MessageDirection.Incoming) return false;
            return true;
        }
    }
}
