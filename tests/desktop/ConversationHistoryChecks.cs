// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AppShield.Conversation;

internal static class ConversationHistoryChecks
{
    private static ConversationLine[] Incoming(params string[] texts) =>
        texts.Select(text => new ConversationLine(MessageDirection.Incoming, text)).ToArray();

    internal static void Run(string root)
    {
        var home = Path.Combine(root, "conversation-history");
        var history = new ConversationHistory(home);
        string title = "Fixture Target " + Guid.NewGuid().ToString("N");
        string marker = "private-fixture-" + Guid.NewGuid().ToString("N");
        var sample = Incoming(marker, "OK");
        var first = history.BeginSegment(title, sample, history.Read(title).Revision);
        var again = history.Merge(title, sample, first.Revision);
        DesktopChecks.Assert(again.Lines.Count == 2 && again.Revision == first.Revision, "identical visible frame is idempotent");

        var repeated = history.Merge(title, Incoming(marker, "OK", "OK"), again.Revision);
        DesktopChecks.Assert(repeated.Lines.Count == 3 && repeated.Lines[1].Text == repeated.Lines[2].Text &&
            repeated.ConfirmedAppendFrom == again.Revision,
            "a repeated real text survives when the previous frame supplies a unique anchor");
        var ambiguous = history.Merge(title, Incoming("OK", "OK", "then"), repeated.Revision);
        DesktopChecks.Assert(ambiguous.HasGap && !ambiguous.ConfirmedAppendFrom.HasValue && ambiguous.Lines.Count == 4 &&
            ambiguous.ContextLines.Select(row => row.Text).SequenceEqual(new[] {"OK", "OK", "then"}),
            "ambiguous overlap retains the observed frame and limits context to it");
        var disjoint = history.Merge(title, Incoming("later", "event"), ambiguous.Revision);
        DesktopChecks.Assert(disjoint.ContextLines.Count == 2 && disjoint.ContextLines[0].GapBefore &&
            history.Merge(title, new ConversationLine[0], disjoint.Revision).Revision == disjoint.Revision,
            "a missing overlap records a gap and an empty observation invents no rows");

        var explicitLines = new[] {new ConversationLine(MessageDirection.Unknown, "pasted-one")};
        var manual = history.AppendManual(title, explicitLines, disjoint.Revision);
        var self = history.AppendManual(title, new[] {new ConversationLine(MessageDirection.Outgoing, "pasted-two")}, manual.Revision);
        DesktopChecks.Assert(self.ContextLines.Count == 2 && self.ContextLines[0].Direction == MessageDirection.Unknown &&
            self.ContextLines[1].Direction == MessageDirection.Outgoing, "manual excerpt keeps stated directions across entries");
        var rebound = history.BeginSegment(title, new ConversationLine[0], self.Revision);
        DesktopChecks.Assert(rebound.ContextLines.Count == 0 && rebound.Lines.Count == self.Lines.Count &&
            new ConversationHistory(home).Read(title).ContextLines.Count == 0,
            "confirming an empty reopened window excludes old content from the next draft");
        var fresh = history.Merge(title, Incoming("fresh"), rebound.Revision);
        DesktopChecks.Assert(fresh.ContextLines.Count == 1 && fresh.ContextLines[0].Text == "fresh",
            "newly bound window begins a fresh context even under the same display title");

        var protectedBytes = File.ReadAllBytes(Path.Combine(home, "ConversationHistory", "history.bin"));
        string stored = Encoding.UTF8.GetString(protectedBytes);
        DesktopChecks.Assert(!stored.Contains(marker) && !stored.Contains(title) &&
            !Directory.GetFileSystemEntries(Path.Combine(home,"ConversationHistory")).Any(p => p.Contains(title)),
            "message contents and target label do not appear in files or filenames");
        var another = history.BeginSegment("Fixture Other", Incoming("separate"));
        DesktopChecks.Assert(another.Lines.Count == 1 && history.Read(title).ContextLines[0].Text == "fresh",
            "independent chosen targets retain separate histories");

        var writers = Enumerable.Range(0, 4).Select(i => Task.Run(() =>
        {
            try
            {
                new ConversationHistory(home).AppendManual(title, Incoming("candidate " + i), fresh.Revision);
                return 1;
            }
            catch (InvalidOperationException) { return 0; }
        })).ToArray();
        Task.WaitAll(writers);
        DesktopChecks.Assert(writers.Sum(task => task.Result) == 1, "only one concurrent writer can publish a stale-revision race");
        var old = history.Read(title);
        string pending = Path.Combine(home,"ConversationHistory","history.bin.pending");
        File.WriteAllBytes(pending, protectedBytes);
        var deleted = history.Delete(title, old.Revision);
        bool rejected = false;
        try { history.Merge(title, Incoming("late result"), old.Revision); }
        catch (InvalidOperationException) { rejected = true; }
        DesktopChecks.Assert(rejected && !File.Exists(pending) && deleted.ContextLines.Count == 0 && history.Read(title).Lines.Count == 0 &&
            history.Read("Fixture Other").ContextLines.Count == 1, "delete prevents a late sample from recreating a cleared conversation");

        var identified = Enumerable.Range(0,6).Select(i => new ConversationLine(MessageDirection.Incoming, "same text", "fixture-" + i)).ToArray();
        var start = history.BeginSegment(title, identified.Take(3).ToArray(), deleted.Revision);
        var advanced = history.Merge(title, identified.Skip(2).Take(3).ToArray(), start.Revision);
        var backwards = history.Merge(title, identified.Take(3).ToArray(), advanced.Revision);
        DesktopChecks.Assert(advanced.Lines.Count == 5 && !advanced.HasGap && backwards.Revision == advanced.Revision,
            "durable message IDs distinguish equal text and a backward scroll cannot replay old rows");
        var bounded = history.BeginSegment(title, Enumerable.Range(0,120).Select(i =>
            new ConversationLine(MessageDirection.Unknown,"batch-a-" + i)).ToArray());
        for (int batch = 0; batch < 2; batch++)
            bounded = history.AppendManual(title, Enumerable.Range(0,120).Select(i =>
                new ConversationLine(MessageDirection.Outgoing,"batch-" + batch + "-" + i)).ToArray(), bounded.Revision);
        DesktopChecks.Assert(bounded.Lines.Count == 256 && bounded.Lines[0].GapBefore &&
            bounded.Lines.Last().Text == "batch-1-119", "retention is bounded and the truncated start is explicitly marked");
    }
}
