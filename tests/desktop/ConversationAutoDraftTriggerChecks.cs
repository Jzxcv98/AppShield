// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Linq;
using AppShield.Conversation;

internal static class ConversationAutoDraftTriggerChecks
{
    private static ConversationLine Row(string text, MessageDirection direction = MessageDirection.Incoming, bool gap = false) =>
        new ConversationLine(direction, text, null, gap);
    private static ConversationSnapshot Frame(long revision, params ConversationLine[] lines) =>
        new ConversationSnapshot(revision, lines.ToList(), false, revision - 1);

    internal static void Run()
    {
        const string key = "bound-fixture";
        var t = new DateTime(2020,1,1,0,0,0,DateTimeKind.Utc);
        var trigger = new ConversationAutoDraftTrigger();
        var before = Row("initial history");
        var first = Frame(1,before);
        trigger.Bind(key,first);
        DesktopChecks.Assert(!trigger.TryTake(key,1,t.AddMinutes(1)), "historical incoming preview does not schedule GPT");
        var a = Row("first live"); var b = Row("second live");
        var second = Frame(2,before,a);
        var third = Frame(3,before,a,b);
        trigger.Observe(key,first,second,t);
        trigger.Observe(key,second,third,t.AddSeconds(7));
        DesktopChecks.Assert(!trigger.Observe(key,third,third,t.AddSeconds(12)) &&
            !trigger.TryTake(key,3,t.AddSeconds(16.9)) && trigger.TryTake(key,3,t.AddSeconds(17)) &&
            trigger.IsCurrent(key,3) && !trigger.TryTake(key,3,t.AddMinutes(2)),
            "successive incoming messages debounce, repeated polls do not reset it, a revision is consumed once");

        var own = Row("already answered", MessageDirection.Outgoing);
        var answered = Frame(4,before,a,b,own);
        DesktopChecks.Assert(trigger.Observe(key,third,answered,t.AddSeconds(18)) && !trigger.IsCurrent(key,3) &&
            !trigger.TryTake(key,4,t.AddMinutes(2)), "own reply invalidates the dispatched draft");
        var question = Row("another question"); var unknown = Row("unattributed", MessageDirection.Unknown);
        var pending = Frame(5,before,a,b,own,question);
        var unclear = Frame(6,before,a,b,own,question,unknown);
        trigger.Observe(key,answered,pending,t);
        trigger.Observe(key,pending,unclear,t.AddSeconds(3));
        DesktopChecks.Assert(!trigger.TryTake(key,6,t.AddMinutes(2)), "unattributed row cancels pending automatic work");

        var gap = Row("new visible excerpt",gap:true);
        var separated = Frame(7,before,a,b,own,question,unknown,gap);
        var reliable = Frame(8,before,a,b,own,question,unknown,gap,Row("next actual incoming"));
        trigger.Observe(key,unclear,separated,t);
        DesktopChecks.Assert(!trigger.TryTake(key,7,t.AddSeconds(30)), "a new discontinuous excerpt becomes baseline only");
        trigger.Observe(key,separated,reliable,t);
        DesktopChecks.Assert(trigger.TryTake(key,8,t.AddSeconds(10)), "an older gap does not permanently suppress reliable later incoming");
        var visuallyIdenticalGap = new ConversationSnapshot(9, reliable.Lines.Concat(new[]{Row("uncertain new")}).ToList(), false);
        trigger.Observe(key,reliable,visuallyIdenticalGap,t.AddSeconds(12));
        DesktopChecks.Assert(!trigger.TryTake(key,9,t.AddMinutes(2)), "a gap already marked at the same row cannot disguise an ambiguous new sample");
        trigger.Reset();
        DesktopChecks.Assert(!trigger.IsCurrent(key,8) && !trigger.TryTake(key,8,t.AddMinutes(2)), "pause invalidates old requests");

        trigger.Bind(key,first);
        trigger.Observe(key,first,second,t);
        DesktopChecks.Assert(!trigger.TryTake("different",2,t.AddSeconds(15)) &&
            !trigger.TryTake(key,2,t.AddSeconds(30)), "switching binding cannot later revive an expired pending request");

        trigger.Bind(key,Frame(0));
        trigger.Observe(key,Frame(0),first,t);
        DesktopChecks.Assert(!trigger.TryTake(key,1,t.AddMinutes(2)), "initial history loaded after an empty baseline stays historical");
        trigger.Bind(key,third);
        var clipped = Frame(9,a,b,Row("new but previous prefix was clipped"));
        trigger.Observe(key,third,clipped,t);
        DesktopChecks.Assert(!trigger.TryTake(key,9,t.AddMinutes(2)), "truncated overlap cannot queue an automatic request");
    }
}
