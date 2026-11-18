// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Threading;
using System.Threading.Tasks;
using AppShield.Conversation;

internal static class ConversationDraftChecks
{
    private sealed class FakeApi : HttpMessageHandler
    {
        internal int Calls;
        internal string Preview;
        internal bool Refuse;
        internal string Action = "reply";
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancel)
        {
            Calls++;
            if (request.Method != HttpMethod.Post || request.RequestUri.AbsoluteUri != "https://api.openai.com/v1/responses" ||
                request.Headers.Authorization?.Scheme != "Bearer" || request.Headers.Authorization.Parameter != "test-only")
                throw new Exception("Wrong request destination or key precedence.");
            string body = await request.Content.ReadAsStringAsync().ConfigureAwait(false);
            if (!body.Contains("\"store\":false") || body.Contains("test-only") || !body.Contains(Preview) ||
                !body.Contains("\"type\":\"json_schema\""))
                throw new Exception("Unexpected request content.");
            return Refuse
                ? new HttpResponseMessage(HttpStatusCode.Unauthorized) { Content = new StringContent("sensitive diagnostic") }
                : new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(
                    "{\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"{\\\"action\\\":\\\"" +
                    Action + "\\\",\\\"text\\\":\\\"synthetic draft\\\"}\"}]}]}") };
        }
    }

    internal static void Run(string dir)
    {
        var handler = new FakeApi { Preview = "reviewed fixture" };
        using (var client = new HttpClient(handler))
        using (var typed = new SecureString())
        {
            foreach (char ch in "test-only") typed.AppendChar(ch);
            var service = new ConversationDraftService(client, null);
            var lines = new[] { new ConversationLine(MessageDirection.Unknown, handler.Preview) };
            string prompt = ConversationDraftService.BuildPrompt(lines, true, "reply briefly");
            DesktopChecks.Assert(prompt.Contains(handler.Preview) && prompt.Contains("方向未知") && prompt.Contains("可能缺少"),
                "approved prompt preserves unknown direction and context gaps");
            var result = service.EvaluateAsync(prompt, typed, CancellationToken.None).GetAwaiter().GetResult();
            DesktopChecks.Assert(result.Kind == DraftDecisionKind.Reply && result.Text == "synthetic draft" && handler.Calls == 1,
                "one reply request uses the session key and only the approved context");
            handler.Action = "clarify";
            var clarify = service.EvaluateAsync(prompt, typed, CancellationToken.None).GetAwaiter().GetResult();
            handler.Action = "no_reply";
            var skip = service.EvaluateAsync(prompt, typed, CancellationToken.None).GetAwaiter().GetResult();
            DesktopChecks.Assert(clarify.Kind == DraftDecisionKind.Clarify && skip.Kind == DraftDecisionKind.NoReply,
                "private clarification and no-reply decisions are distinguished from sendable replies");
            handler.Refuse = true;
            try { service.EvaluateAsync(prompt, typed, CancellationToken.None).GetAwaiter().GetResult(); throw new Exception("Expected refusal"); }
            catch (InvalidOperationException ex) { DesktopChecks.Assert(!ex.Message.Contains("sensitive diagnostic"), "API errors omit response content"); }
            string config = Path.Combine(dir, "conversation-config-test.json");
            File.WriteAllText(config, "{\"apiKey\":\"test-only\"}");
            try { new ConversationDraftService(client, config).EvaluateAsync(prompt, typed, CancellationToken.None).GetAwaiter().GetResult(); throw new Exception("Expected invalid config"); }
            catch (InvalidDataException) { DesktopChecks.Assert(handler.Calls == 4, "config with a secret field is rejected before any request"); }
        }
    }

    // Explicit live smoke test with a fixed synthetic input; there is no capture or history access here.
    internal static int SyntheticApi()
    {
        try
        {
            var rows = new[] { new ConversationLine(MessageDirection.Incoming, "这是合成测试。白板演示改到几点？") };
            string prompt = ConversationDraftService.BuildPrompt(rows, false, "回复演示在下午三点开始，简短即可。");
            var result = new ConversationDraftService().EvaluateAsync(prompt, null, CancellationToken.None).GetAwaiter().GetResult();
            if (result.Kind != DraftDecisionKind.Reply || string.IsNullOrWhiteSpace(result.Text)) throw new InvalidDataException("Missing synthetic reply");
            Console.WriteLine("PASS: live OpenAI response to a fixed synthetic prompt; no WeChat content was accessed.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }
    }
}
