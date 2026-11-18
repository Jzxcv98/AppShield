// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Automation;

namespace AppShield.Conversation
{
    // The 4.2 text-row provider can expose a viewport-wide rectangle with no text geometry.
    // Inspect four tiny patches of the verified row, only while visible in its own window.
    // No screen/window bitmap is retained and no pixels are included in history or API input.
    internal static class WeChatRenderedBubbleSide
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct PointI { public int X, Y; public PointI(int x, int y) { X = x; Y = y; } }
        [DllImport("user32.dll")] private static extern IntPtr WindowFromPhysicalPoint(PointI point);
        [DllImport("user32.dll")] private static extern IntPtr GetAncestor(IntPtr window, uint flag);
        [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out int pid);
        [DllImport("user32.dll")] private static extern IntPtr SetThreadDpiAwarenessContext(IntPtr context);
        [DllImport("user32.dll")] private static extern uint GetDpiForWindow(IntPtr window);
        [DllImport("user32.dll")] private static extern bool ScreenToClient(IntPtr window, ref PointI point);
        [DllImport("user32.dll")] private static extern IntPtr GetDCEx(IntPtr window, IntPtr clip, uint flags);
        [DllImport("user32.dll")] private static extern int ReleaseDC(IntPtr window, IntPtr dc);
        [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleDC(IntPtr dc);
        [DllImport("gdi32.dll")] private static extern IntPtr CreateCompatibleBitmap(IntPtr dc, int width, int height);
        [DllImport("gdi32.dll")] private static extern IntPtr SelectObject(IntPtr dc, IntPtr obj);
        [DllImport("gdi32.dll")] private static extern bool DeleteObject(IntPtr obj);
        [DllImport("gdi32.dll")] private static extern bool DeleteDC(IntPtr dc);
        [DllImport("gdi32.dll")] private static extern bool BitBlt(IntPtr target, int x, int y, int width, int height, IntPtr source, int sx, int sy, uint op);
        [DllImport("gdi32.dll")] private static extern uint GetPixel(IntPtr dc, int x, int y);

        internal static MessageDirection Read(IntPtr root, AutomationElement list, AutomationElement row, Func<bool> stillBound)
        {
            if (root == IntPtr.Zero || !stillBound() || row.Current.ClassName != "mmui::ChatTextItemView" ||
                row.Current.IsOffscreen || list.Current.ProcessId != row.Current.ProcessId ||
                GetWindowThreadProcessId(root, out int pid) == 0 || pid != row.Current.ProcessId)
                return MessageDirection.Unknown;
            Rect bounds = row.Current.BoundingRectangle, viewport = list.Current.BoundingRectangle;
            double scale = GetDpiForWindow(root) / 96.0;
            if (scale < 0.75 || scale > 5 || bounds.IsEmpty || !viewport.Contains(bounds) ||
                bounds.Width < 270*scale || bounds.Height < 28*scale || bounds.Height > 130*scale)
                return MessageDirection.Unknown;
            IntPtr previous = SetThreadDpiAwarenessContext(new IntPtr(-4));
            if (previous == IntPtr.Zero) return MessageDirection.Unknown;
            try
            {
                // Edge patches establish the row's own background. The inner strips are just
                // inside the bubble's avatar-facing edge, keeping avatars outside the samples.
                uint[][] patches = new uint[4][];
                double[] near = { 5, 72, 72, 5 };
                for (int k=0; k<4; k++)
                {
                    bool fromRight = k >= 2;
                    double width = (k == 0 || k == 3 ? 6 : 19) * scale;
                    int x = (int)Math.Round(fromRight ? bounds.Right-near[k]*scale-width : bounds.Left+near[k]*scale);
                    int height = Math.Max(5,(int)Math.Round(Math.Min(17*scale, bounds.Height*0.34)));
                    int y = (int)Math.Round(bounds.Top + bounds.Height*0.5 - height*0.5);
                    patches[k] = Sample(root, pid, x, y, (int)Math.Round(width), height);
                    if (patches[k] == null) return MessageDirection.Unknown;
                }
                if (!stillBound() || bounds != row.Current.BoundingRectangle || viewport != list.Current.BoundingRectangle)
                    return MessageDirection.Unknown;
                return Classify(patches[0],patches[1],patches[2],patches[3]);
            }
            finally { SetThreadDpiAwarenessContext(previous); }
        }

        private static uint[] Sample(IntPtr root, int pid, int x, int y, int width, int height)
        {
            var points = new PointI[15];
            for (int j=0; j<3; j++)
                for (int i=0; i<5; i++)
                    points[j*5+i] = new PointI(x+i*(width-1)/4, y+j*(height-1)/2);
            var leaf = WindowFromPhysicalPoint(points[0]);
            if (leaf == IntPtr.Zero || GetAncestor(leaf,2) != root || GetWindowThreadProcessId(leaf,out int windowPid)==0 || windowPid!=pid ||
                !Array.TrueForAll(points,p => WindowFromPhysicalPoint(p)==leaf)) return null;
            var source = GetDCEx(leaf,IntPtr.Zero,0x0002 | 0x0010 /* cached client DC clipped to siblings */);
            if (source==IntPtr.Zero) return null;
            IntPtr sink=IntPtr.Zero, bitmap=IntPtr.Zero, old=IntPtr.Zero;
            try
            {
                var start = new PointI(x,y);
                if (!ScreenToClient(leaf,ref start)) return null;
                sink=CreateCompatibleDC(source); bitmap=CreateCompatibleBitmap(source,width,height);
                if (sink==IntPtr.Zero || bitmap==IntPtr.Zero) return null;
                old=SelectObject(sink,bitmap);
                if (old==IntPtr.Zero || old==new IntPtr(-1) ||
                    !BitBlt(sink,0,0,width,height,source,start.X,start.Y,0x00CC0020)) return null;
                uint[] values=Array.ConvertAll(points,p => GetPixel(sink,p.X-x,p.Y-y));
                return Array.IndexOf(values,uint.MaxValue)>=0 || !Array.TrueForAll(points,p => WindowFromPhysicalPoint(p)==leaf) ? null : values;
            }
            finally
            {
                if(old!=IntPtr.Zero && old!=new IntPtr(-1)) SelectObject(sink,old);
                if(bitmap!=IntPtr.Zero) DeleteObject(bitmap);
                if(sink!=IntPtr.Zero) DeleteDC(sink);
                ReleaseDC(leaf,source);
            }
        }

        private static int R(uint c) => (int)(c & 255);
        private static int G(uint c) => (int)((c>>8) & 255);
        private static int B(uint c) => (int)((c>>16) & 255);
        private static int Distance(uint a,uint b) => Math.Max(Math.Abs(R(a)-R(b)),Math.Max(Math.Abs(G(a)-G(b)),Math.Abs(B(a)-B(b))));
        private static bool Consensus(uint[] values,uint expected,int threshold) =>
            Array.FindAll(values,c => Distance(c,expected)<=threshold).Length >= 11;

        internal static MessageDirection Classify(uint[] leftEdge, uint[] left, uint[] right, uint[] rightEdge)
        {
            if (leftEdge?.Length!=15 || left?.Length!=15 || right?.Length!=15 || rightEdge?.Length!=15)
                return MessageDirection.Unknown;
            uint background=leftEdge[7];
            if (!Consensus(leftEdge,background,7) || !Consensus(rightEdge,background,7)) return MessageDirection.Unknown;
            if (Consensus(left,background,7))
            {
                foreach (uint c in right)
                    if (G(c)>=100 && G(c)-R(c)>=24 && G(c)-B(c)>=18 && Distance(c,background)>=28 && Consensus(right,c,9))
                        return MessageDirection.Outgoing;
            }
            if (Consensus(right,background,7))
            {
                foreach (uint c in left)
                    if (Math.Max(R(c),Math.Max(G(c),B(c)))-Math.Min(R(c),Math.Min(G(c),B(c)))<=15 &&
                        ((Distance(c,background)>=14 && Consensus(left,c,7)) ||
                         (Distance(c,background)>=9 && Array.FindAll(left,p => Distance(p,c)<=2).Length>=13 &&
                          Array.FindAll(right,p => Distance(p,background)<=2).Length>=13)))
                        return MessageDirection.Incoming;
            }
            return MessageDirection.Unknown;
        }
    }
}
