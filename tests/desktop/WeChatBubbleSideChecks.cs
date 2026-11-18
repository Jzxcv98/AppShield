// SPDX-License-Identifier: GPL-3.0-only
using System.Linq;
using System.Windows;
using AppShield.Conversation;

internal static class WeChatBubbleSideChecks
{
    internal static void Run()
    {
        var dark = System.Linq.Enumerable.Repeat(0x202020u, 15).ToArray();
        var green = System.Linq.Enumerable.Repeat(0x88C838u, 15).ToArray();
        var grey = System.Linq.Enumerable.Repeat(0x434343u, 15).ToArray();
        var light = Enumerable.Repeat(0xf5f5f5u, 15).ToArray();
        var white = Enumerable.Repeat(0xffffffu, 15).ToArray();
        DesktopChecks.Assert(WeChatRenderedBubbleSide.Classify(dark, dark, green, dark) == MessageDirection.Outgoing &&
            WeChatRenderedBubbleSide.Classify(dark, grey, dark, dark) == MessageDirection.Incoming &&
            WeChatRenderedBubbleSide.Classify(light, white, light, light) == MessageDirection.Incoming &&
            WeChatRenderedBubbleSide.Classify(dark, grey, green, dark) == MessageDirection.Unknown &&
            WeChatRenderedBubbleSide.Classify(dark, dark, dark, dark) == MessageDirection.Unknown &&
            WeChatRenderedBubbleSide.Classify(dark, grey, dark, grey) == MessageDirection.Unknown,
            "visible bubble-side samples require coherent aligned fill and matching background on both edges");
        // Offset including a negative screen coordinate represents a second monitor.
        var list = new Rect(-500, 50, 800, 480);
        var row = new Rect(-490, 60, 775, 70);
        var left = new Rect(-410, 65, 125, 22);
        var right = new Rect(105, 65, 85, 22);
        DesktopChecks.Assert(WeChatBubbleSide.Classify(list, left) == MessageDirection.Incoming &&
            WeChatBubbleSide.Classify(list, right) == MessageDirection.Outgoing, "clearly left and right bubble geometry is classified");
        DesktopChecks.Assert(WeChatBubbleSide.Classify(list, row) == MessageDirection.Unknown &&
            WeChatBubbleSide.Classify(list, new Rect(-148, 72, 95, 25)) == MessageDirection.Unknown &&
            WeChatBubbleSide.Classify(list, new Rect(-403, 72, 410, 25)) == MessageDirection.Unknown &&
            WeChatBubbleSide.Classify(list, new Rect(-510, 72, 100, 25)) == MessageDirection.Unknown,
            "full-row, centered, center-crossing and clipped geometry cannot establish the sender");
        DesktopChecks.Assert(WeChatBubbleSide.ClassifyRange(list, row, new[] {right, new Rect(80, 89, 110, 22)}) ==
            MessageDirection.Outgoing && WeChatBubbleSide.ClassifyRange(list,row,new[]{left,right}) == MessageDirection.Unknown &&
            WeChatBubbleSide.ClassifyRange(list,row,new[]{new Rect(-410, 40, 125, 22)}) == MessageDirection.Unknown &&
            WeChatBubbleSide.ClassifyRange(list,row,new Rect[0]) == MessageDirection.Unknown,
            "multi-line range geometry is scoped to the same row and needs unambiguous alignment");
    }
}
