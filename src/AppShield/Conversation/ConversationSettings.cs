// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Web.Script.Serialization;

namespace AppShield.Conversation
{
    internal static class ConversationSettings
    {
        internal static IEnumerable<string> Paths(string file)
        {
            var binaryDir = new DirectoryInfo(Path.GetDirectoryName(typeof(ConversationSettings).Assembly.Location));
            var root = binaryDir.Parent?.Parent;
            if (root != null && string.Equals(binaryDir.Parent.Name, "build", StringComparison.OrdinalIgnoreCase) &&
                File.Exists(Path.Combine(root.FullName, "src", "AppShield", "AppShield.csproj")))
                yield return Path.Combine(root.FullName, ".local", file);
            yield return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AppShield", file);
        }

        internal static bool IsExcludedTitle(string title)
        {
            if (string.IsNullOrWhiteSpace(title)) return true;
            string normal = title.Trim().Normalize(NormalizationForm.FormKC);
            try
            {
                foreach (string path in Paths("conversation-exclusions.json"))
                {
                    // File.Exists also reports false on access errors. Only an absent optional
                    // file may be ignored; an unreadable exclusion list must stop collection.
                    try { File.GetAttributes(path); }
                    catch (FileNotFoundException) { continue; }
                    catch (DirectoryNotFoundException) { continue; }
                    using (var input = SafeFiles.OpenRead(path, true))
                    using (var reader = new StreamReader(input, Encoding.UTF8, true))
                    {
                        if (input.Length > 16384) return true;
                        var names = new JavaScriptSerializer().DeserializeObject(reader.ReadToEnd()) as object[];
                        if (names == null || names.Any(x => !(x is string))) return true;
                        if (names.Cast<string>().Any(n => string.Equals(n.Trim().Normalize(NormalizationForm.FormKC),
                            normal, StringComparison.OrdinalIgnoreCase))) return true;
                    }
                }
            }
            catch (Exception ex) when (ex is ArgumentException || ex is InvalidOperationException ||
                ex is IOException || ex is UnauthorizedAccessException || ex is System.Security.SecurityException)
            { return true; }
            return false;
        }
    }
}
