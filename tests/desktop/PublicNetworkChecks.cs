// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;

internal static class PublicNetworkChecks
{
    internal const string Host = "www.microsoft.com";

    // An environment that resolves this name to a local proxy is not a public egress control.
    private static bool GloballyRoutable(AddressFamily family, byte[] ip)
    {
        if (family != AddressFamily.InterNetwork) return false;
        return ip[0] != 0 && ip[0] != 10 && ip[0] != 127 && ip[0] < 224 &&
            !(ip[0] == 100 && ip[1] >= 64 && ip[1] <= 127) && !(ip[0] == 169 && ip[1] == 254) &&
            !(ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) && !(ip[0] == 192 && ip[1] == 168) &&
            !(ip[0] == 192 && ip[1] == 0) && !(ip[0] == 198 && (ip[1] == 18 || ip[1] == 19)) &&
            !(ip[0] == 198 && ip[1] == 51 && ip[2] == 100) && !(ip[0] == 203 && ip[1] == 0 && ip[2] == 113);
    }

    internal static bool Connect(IPAddress address)
    {
        using (var client = new TcpClient(address.AddressFamily))
        {
            try { return client.ConnectAsync(address, 443).Wait(TimeSpan.FromSeconds(5)) && client.Connected; }
            catch (AggregateException error) when (error.GetBaseException() is SocketException) { return false; }
            catch (SocketException) { return false; }
        }
    }

    internal static IPAddress SelectEndpoint()
    {
        try {
            return Dns.GetHostAddresses(Host).Where(ip => GloballyRoutable(ip.AddressFamily, ip.GetAddressBytes()))
                .Take(4).FirstOrDefault(Connect);
        } catch (SocketException) { return null; }
    }
}
