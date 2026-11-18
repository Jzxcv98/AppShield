// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Automation;

namespace AppShield.Conversation
{
    // Caller verifies the foreground conversation, its message list, and the fixed text-bubble
    // item ID. This class looks only within that individual row; no screenshot or text is fetched.
    internal static class WeChatBubbleSide
    {
        internal static MessageDirection Read(AutomationElement verifiedList, AutomationElement verifiedTextRow,
            string verifiedBody = null)
        {
            if (verifiedList == null || verifiedTextRow == null) return MessageDirection.Unknown;
            try
            {
                int pid = verifiedList.Current.ProcessId;
                if (pid <= 0 || verifiedTextRow.Current.ProcessId != pid || verifiedTextRow.Current.IsOffscreen ||
                    !DirectChild(verifiedTextRow, verifiedList)) return MessageDirection.Unknown;
                Rect list = verifiedList.Current.BoundingRectangle, row = verifiedTextRow.Current.BoundingRectangle;
                MessageDirection result = Classify(list, row);
                if (result == MessageDirection.Unknown && FullWidth(list, row))
                {
                    // A viewport-width row does not describe the bubble. Both alternatives
                    // below must concern this same row. Conflicting evidence stays unknown.
                    MessageDirection pattern = FromRange(verifiedTextRow, list, row);
                    MessageDirection label = FromOnlyTextChild(verifiedTextRow, list, row, pid, verifiedBody);
                    result = pattern == MessageDirection.Unknown ? label :
                        label == MessageDirection.Unknown || label == pattern ? pattern : MessageDirection.Unknown;
                }
                // Discard a result computed while the list was scrolling or the window was moving.
                return result != MessageDirection.Unknown && verifiedTextRow.Current.BoundingRectangle == row &&
                    verifiedList.Current.BoundingRectangle == list && DirectChild(verifiedTextRow,verifiedList)
                    ? result : MessageDirection.Unknown;
            }
            catch (ElementNotAvailableException) { return MessageDirection.Unknown; }
            catch (InvalidOperationException) { return MessageDirection.Unknown; }
            catch (NotSupportedException) { return MessageDirection.Unknown; }
            catch (COMException) { return MessageDirection.Unknown; }
        }

        private static bool DirectChild(AutomationElement child, AutomationElement expected)
        {
            var parent = TreeWalker.ControlViewWalker.GetParent(child);
            return parent != null && Automation.Compare(parent, expected);
        }

        private static MessageDirection FromRange(AutomationElement row, Rect list, Rect bounds)
        {
            if (!row.TryGetCurrentPattern(TextPattern.Pattern, out var value) || !(value is TextPattern pattern))
                return MessageDirection.Unknown;
            return ClassifyRange(list, bounds, pattern.DocumentRange.GetBoundingRectangles());
        }

        private static MessageDirection FromOnlyTextChild(AutomationElement row, Rect list, Rect bounds,
            int pid, string verifiedBody)
        {
            if (string.IsNullOrEmpty(verifiedBody)) return MessageDirection.Unknown;
            var condition = new AndCondition(new PropertyCondition(AutomationElement.ControlTypeProperty, ControlType.Text),
                new PropertyCondition(AutomationElement.ProcessIdProperty, pid),
                new PropertyCondition(AutomationElement.IsOffscreenProperty, false));
            var labels = row.FindAll(TreeScope.Children, condition);
            if (labels.Count != 1 || !DirectChild(labels[0], row)) return MessageDirection.Unknown;
            // Check a fixed value we already have; never read arbitrary labels such as sender captions.
            var checkName = new PropertyCondition(AutomationElement.NameProperty, verifiedBody);
            if (labels[0].FindFirst(TreeScope.Element, checkName) == null) return MessageDirection.Unknown;
            var box = labels[0].Current.BoundingRectangle;
            return Contains(bounds, box) ? Classify(list, box) : MessageDirection.Unknown;
        }

        internal static MessageDirection ClassifyRange(Rect list, Rect row, Rect[] rectangles)
        {
            if (!FullWidth(list, row) || rectangles == null || rectangles.Length == 0 || rectangles.Length > 64)
                return MessageDirection.Unknown;
            Rect union = Rect.Empty;
            foreach (var rectangle in rectangles)
            {
                if (!Contains(row, rectangle)) return MessageDirection.Unknown;
                union.Union(rectangle);
            }
            return Classify(list, union);
        }

        internal static MessageDirection Classify(Rect list, Rect evidence)
        {
            if (!Contains(list, evidence) || list.Width < 96 || evidence.Width < 2 || evidence.Height < 2)
                return MessageDirection.Unknown;
            double left = (evidence.Left - list.Left) / list.Width;
            double right = (evidence.Right - list.Left) / list.Width;
            double middle = (left + right) / 2;
            if (right <= 0.45 && middle <= 0.30) return MessageDirection.Incoming;
            if (left >= 0.55 && middle >= 0.70) return MessageDirection.Outgoing;
            return MessageDirection.Unknown;
        }

        private static bool FullWidth(Rect list, Rect row) => Contains(list, row) &&
            row.Left <= list.Left + list.Width * 0.12 && row.Right >= list.Right - list.Width * 0.12;

        private static bool Contains(Rect outer, Rect inner) =>
            FiniteBox(outer) && FiniteBox(inner) && outer.Contains(inner);

        private static bool FiniteBox(Rect r) => !r.IsEmpty && r.Width > 0 && r.Height > 0 &&
            Finite(r.Left) && Finite(r.Top) && Finite(r.Right) && Finite(r.Bottom);

        private static bool Finite(double value) => !double.IsNaN(value) && !double.IsInfinity(value);
    }
}
