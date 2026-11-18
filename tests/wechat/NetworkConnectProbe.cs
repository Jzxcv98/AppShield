// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;

internal static class NetworkConnectProbe
{
    // A fresh TCP connection only. Never sends application data.
    private static int Main(string[] args)
    {
        IPAddress endpoint;
        if (args.Length != 2 || !IPAddress.TryParse(args[0], out endpoint)) return 90;
        using (var id = WindowsIdentity.GetCurrent())
        {
            if (id.User.Value != args[1] || new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator)) return 91;
        }
        using (var socket = new Socket(endpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp))
        {
            try
            {
                var result = socket.BeginConnect(endpoint, 443, null, null);
                using (var wait = result.AsyncWaitHandle)
                    if (!wait.WaitOne(5000)) return 42;
                socket.EndConnect(result);
                return 0;
            }
            catch (SocketException e) { return e.SocketErrorCode == SocketError.AccessDenied ? 41 : 43; }
        }
    }
}
