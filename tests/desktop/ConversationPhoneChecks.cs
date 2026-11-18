// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Threading;
using AppShield;
using AppShield.Conversation;

internal static class ConversationPhoneChecks
{
    // The test observes an already foregrounded conversation. It only asks UIA about an exact
    // synthetic label, never brings WeChat to the foreground and never opens conversations.
    internal static int Run(string[] args)
    {
        int seconds = 120;
        if (args == null || args.Length < 2 || args.Length > 3 ||
            (args.Length == 3 && (!int.TryParse(args[2], out seconds) || seconds < 1 || seconds > 300)) ||
            !IsSyntheticMarker(args[1]))
        {
            Console.Error.WriteLine("Usage: --conversation-phone-marker FileTransfer|Self AS-<unique-test-marker> [1..300]");
            return 2;
        }
        bool self = args[0] == "Self";
        IEnumerable<string> titles;
        if (self)
        {
            string name = Environment.GetEnvironmentVariable("APPSHIELD_PHONE_SELF_TITLE");
            if (!WeChatVisibleConversation.IsAllowedTitle(name,true))
            { Console.Error.WriteLine("A confirmed, permitted self-conversation title is required."); return 2; }
            titles = new[]{name};
        }
        else if (args[0] == "FileTransfer") titles = WeChatVisibleConversation.FileTransferTitles;
        else { Console.Error.WriteLine("Unsupported test target."); return 2; }

        string root = Path.Combine(Path.GetFullPath(Path.GetTempPath()),"AppShield.ConversationPhone." + Guid.NewGuid().ToString("N"));
        if (Directory.Exists(root)) return 1;
        try
        {
            var profile = new AppService(root).ImportWeChat();
            string boundTitle = null, boundSource = null, previousReport = null;
            int attempts = 0, consecutive = 0, verified = 0;
            var timer = Stopwatch.StartNew();
            Console.WriteLine("WAITING: marker-only foreground or pinned-window test ready; no chat text or notifications collected.");
            do
            {
                VisibleConversationSample result = null;
                foreach (string title in boundTitle == null ? titles : new[]{boundTitle})
                {
                    var candidate=WeChatVisibleConversation.ProbeMarker(profile,title,self,args[1],boundSource); ++attempts;
                    if (candidate.State == VisibleConversationState.Verified)
                    {
                        result=candidate;
                        boundTitle=title; boundSource=result.SourceKey; ++verified;
                        consecutive=result.MarkerSeen ? consecutive + 1 : 0;
                        break;
                    }
                    if(result==null || candidate.Structure!=null || result.State==VisibleConversationState.NotForeground)
                        result=candidate;
                    // A pinned window can carry another locale's title while a non-WeChat
                    // process holds keyboard focus. Give each exact allowed alias a chance.
                    if (timer.Elapsed.TotalSeconds >= seconds) break;
                }
                if (result == null || result.State != VisibleConversationState.Verified) consecutive=0;
                if (consecutive >= 2) { Console.WriteLine("PASS: exact synthetic marker confirmed twice in one bound visible conversation."); return 0; }
                string report = result == null ? "NoTarget" : result.State.ToString() + (result.Structure == null ? "" : " " + result.Structure);
                if (report != previousReport)
                {
                    Console.WriteLine("STATE " + report);
                    previousReport=report;
                }
                Thread.Sleep(500);
            } while(timer.Elapsed.TotalSeconds < seconds);
            Console.WriteLine("UNVERIFIED: no confirmed marker; attempts=" + attempts + " verified-frames=" + verified + ".");
            return 77;
        }
        catch (Exception e)
        {
            // Do not include UIA diagnostics or paths from the inspected computer in public logs.
            Console.Error.WriteLine("ERROR: marker check failed (" + e.GetType().Name + ").");
            return 1;
        }
        finally
        {
            // The only persisted file is the temporary AppShield installation profile. No message data is written.
            if (Directory.Exists(root))
            {
                using (SafeFiles.PinDirectory(root))
                {
                    string profileFile=Path.Combine(root,"Profiles.xml");
                    if (File.Exists(profileFile)) File.Delete(profileFile);
                }
                Directory.Delete(root,false);
            }
        }
    }

    internal static bool IsSyntheticMarker(string text)
    {
        if (text == null || !text.StartsWith("AS-",StringComparison.Ordinal) || text.Length < 9 || text.Length > 72) return false;
        for(int i=3;i<text.Length;i++)
        {
            char c=text[i];
            if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-')) return false;
        }
        return true;
    }
}
