// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Automation;
using AppShield;
using AppShield.Model;

internal static class WeChatWindowMarkers
{
    internal enum Marker { Unknown, ScanToLogin, ClientError }

    private static readonly Condition ScanPrompt = ExactNames("Scan to log in", "Scan QR code to log in",
        "扫码登录", "掃碼登入", "扫描二维码登录", "掃描二維碼登入", "请使用手机微信扫码登录", "請使用手機微信掃碼登入",
        "请使用手机微信扫描二维码登录", "請使用手機微信掃描二維碼登入", "掃描 QR Code 登入");

    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out int processId);

    private static Condition ExactNames(params string[] labels) => new OrCondition(labels.Select(text =>
        (Condition)new PropertyCondition(AutomationElement.NameProperty, text, PropertyConditionFlags.IgnoreCase)).ToArray());

    internal static Marker Read(TextTarget target)
    {
        var window = new IntPtr(target.WindowHandle);
        if (GetWindowThreadProcessId(window, out int owner) == 0 || owner != target.ProcessId) return Marker.Unknown;
        try
        {
            var root = AutomationElement.FromHandle(window);
            var sameProcess = new PropertyCondition(AutomationElement.ProcessIdProperty, owner);
            if (WeChatIntegration.IsLaunchError(target)) return Marker.ClientError;
            // Search only for a visible, fixed prompt. Never request arbitrary names, values, images or QR data.
            var visiblePrompt = new AndCondition(sameProcess, ScanPrompt, new PropertyCondition(AutomationElement.IsOffscreenProperty, false));
            return root.FindFirst(TreeScope.Descendants, visiblePrompt) == null ? Marker.Unknown : Marker.ScanToLogin;
        }
        catch (ElementNotAvailableException) { return Marker.Unknown; }
        catch (UnauthorizedAccessException) { return Marker.Unknown; }
        catch (COMException) { return Marker.Unknown; }
        catch (ArgumentException) { return Marker.Unknown; }
        catch (InvalidOperationException) { return Marker.Unknown; }
    }
}
