// SPDX-License-Identifier: GPL-3.0-only
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Xml;
using System.Xml.Serialization;
using AppShield.Model;

namespace AppShield
{
    internal sealed class ProfileStore
    {
        internal string Root { get; }
        private readonly string file, mutexName;
        private static readonly XmlSerializer Serializer = new XmlSerializer(typeof(List<AppProfile>));

        internal ProfileStore(string root)
        {
            Root = SafeFiles.LocalPath(root);
            file = Path.Combine(Root, "Profiles.xml");
            using (var hash = SHA256.Create())
                mutexName = @"Local\AppShield.Profiles." + Convert.ToBase64String(
                    hash.ComputeHash(Encoding.UTF8.GetBytes(Root.ToUpperInvariant()))).Replace('/', '_');
        }

        internal List<AppProfile> Read() => Locked(ReadCore);

        internal T Change<T>(Func<List<AppProfile>, T> update) => Locked(() => {
            var items = ReadCore();
            var result = update(items);
            SafeFiles.PlainDirectories(Root, true);
            var temp = Path.Combine(Root, Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    Serializer.Serialize(stream, items);
                    stream.Flush(true);
                }
                if (File.Exists(file)) File.Replace(temp, file, null);
                else File.Move(temp, file);
            }
            finally { if (File.Exists(temp)) File.Delete(temp); }
            return result;
        });

        private T Locked<T>(Func<T> action)
        {
            using (var gate = new Mutex(false, mutexName))
            {
                bool acquired;
                try { acquired = gate.WaitOne(TimeSpan.FromSeconds(10)); }
                catch (AbandonedMutexException) { acquired = true; }
                if (!acquired) throw new IOException("其他窗口正在更新配置，请稍后重试。");
                try { return action(); } finally { gate.ReleaseMutex(); }
            }
        }

        private List<AppProfile> ReadCore()
        {
            if (!File.Exists(file)) return new List<AppProfile>();
            using (var stream = SafeFiles.OpenRead(file, true))
            using (var xml = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null, MaxCharactersInDocument = 4 * 1024 * 1024 }))
            {
                var items = (List<AppProfile>)Serializer.Deserialize(xml);
                if (items == null || items.Any(p => p == null || p.Id == Guid.Empty || p.Revision <= 0) ||
                    items.Select(p => p.Id).Distinct().Count() != items.Count)
                    throw new InvalidDataException("应用配置文件无效。");
                return items;
            }
        }
    }
}
