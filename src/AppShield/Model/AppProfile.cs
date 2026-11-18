// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;

namespace AppShield.Model
{
    public sealed class FolderRule
    {
        public string Path { get; set; }
        public bool Writable { get; set; }
        // Only the applied ACL journal fills this. Drafts identify user choices by path.
        public string DirectoryIdentity { get; set; }
    }

    public sealed class AppProfile
    {
        public Guid Id { get; set; }
        public long Revision { get; set; }
        public string Name { get; set; }
        public string ExecutablePath { get; set; }
        public string ImageHash { get; set; }
        public long ImageLength { get; set; }
        public long ImageWriteUtcTicks { get; set; }
        public string ProductVersion { get; set; }
        public string Publisher { get; set; }
        public string PackageFamilyName { get; set; }
        public string PackageAppId { get; set; }
        public bool IsTelegram { get; set; }
        public bool IsWeChat { get; set; }
        public bool AllowInternet { get; set; } = true;
        public bool BlockLoopback { get; set; } = true;
        public bool BlockLan { get; set; } = true;
        public bool AllowTextIn { get; set; }
        public bool AllowTextOut { get; set; }
        public List<FolderRule> Folders { get; set; } = new List<FolderRule>();
    }

    public sealed class TextTarget
    {
        public int ProcessId { get; set; }
        public long WindowHandle { get; set; }
        public long ProcessStartUtcTicks { get; set; }
        public string Label { get; set; }
        public override string ToString() => Label;
    }

    public sealed class WeChatFolderProtection
    {
        public string Path { get; internal set; }
        public string Sid { get; internal set; }
        public string Account { get; internal set; }
        public bool Verified { get; internal set; }
    }

    public sealed class RuntimeReport
    {
        public bool EngineReady { get; set; }
        public bool Applied { get; set; }
        public string EngineDetail { get; set; }
        public string State { get; set; }
        public string Detail { get; set; }
        public int Boxed { get; set; }
        public int Unboxed { get; set; }
        public int Unknown { get; set; }
        public List<TextTarget> Targets { get; set; } = new List<TextTarget>();
    }
}
