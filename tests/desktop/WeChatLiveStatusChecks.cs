// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using AppShield.Native;

internal static class WeChatLiveStatusChecks
{
    internal static void Run()
    {
        using (var self = Process.GetCurrentProcess())
        {
            string path = self.MainModule.FileName;
            var sample = WeChatLiveStatus.ObserveImage(path, 0);
            DesktopChecks.Assert(sample.CurrentUserProcesses >= 1 && sample.SampleUtc.Kind == DateTimeKind.Utc,
                "live inventory confirms the identity and session of this fixture");
            var newerImage = WeChatLiveStatus.ObserveImage(path, DateTime.UtcNow.AddDays(1).ToFileTimeUtc());
            DesktopChecks.Assert(newerImage.CurrentUserProcesses == 0 && newerImage.UnverifiedProcesses >= 1,
                "a process predating the image is excluded from verified process and TCP counts");
        }
    }

    internal static void RunLoopback()
    {
        using (var self = Process.GetCurrentProcess())
        {
            int endpoints = 0;
            foreach (var loopback in new[] { IPAddress.Loopback, IPAddress.IPv6Loopback })
            {
                if (loopback.AddressFamily == AddressFamily.InterNetworkV6 && !Socket.OSSupportsIPv6) continue;
                var server = new TcpListener(loopback, 0);
                server.Start();
                try
                {
                    using (var caller = new TcpClient(loopback.AddressFamily))
                    {
                        caller.Connect((IPEndPoint)server.LocalEndpoint);
                        using (var accepted = server.AcceptTcpClient())
                        {
                            var sample = WeChatLiveStatus.ObserveImage(self.MainModule.FileName, 0);
                            DesktopChecks.Assert(sample.CurrentUserEstablishedTcp >= 2,
                                "established local fixture TCP endpoints counted in " + loopback.AddressFamily);
                        }
                    }
                    endpoints++;
                }
                finally { server.Stop(); }
            }
            DesktopChecks.Assert(endpoints > 0, "at least one local TCP family checked without publishing endpoints");
        }
    }
}
