using System;
using System.Collections.Generic;
using System.Collections.Specialized;

public sealed class RoutingRuleItem {
    public string Kind { get; private set; }
    public string Value { get; private set; }
    public int Sequence { get; private set; }
    public string Group { get; private set; }
    public string Action { get; private set; }
    public string Source { get; private set; }
    public ulong Network { get; private set; }
    public int Prefix { get; private set; }
    public ulong Mask { get; private set; }

    public RoutingRuleItem(string kind, string value, int sequence, string group, string action, string source, ulong network, int prefix, ulong mask) {
        Kind = kind;
        Value = value;
        Sequence = sequence;
        Group = group;
        Action = action;
        Source = source;
        Network = network;
        Prefix = prefix;
        Mask = mask;
    }
}

public sealed class RoutingRuleItemComparer : System.Collections.IComparer {
    private readonly bool comparePrefix;
    private readonly bool compareDomainDepth;

    public static readonly RoutingRuleItemComparer PrefixThenValue = new RoutingRuleItemComparer(true, false);
    public static readonly RoutingRuleItemComparer DomainDepthThenValue = new RoutingRuleItemComparer(false, true);

    private RoutingRuleItemComparer(bool comparePrefix, bool compareDomainDepth) {
        this.comparePrefix = comparePrefix;
        this.compareDomainDepth = compareDomainDepth;
    }

    public int Compare(object leftObject, object rightObject) {
        if (object.ReferenceEquals(leftObject, rightObject)) return 0;
        if (leftObject == null) return -1;
        if (rightObject == null) return 1;

        var left = Unwrap(leftObject);
        var right = Unwrap(rightObject);
        int primaryComparison = 0;
        if (comparePrefix) {
            primaryComparison = left.Prefix.CompareTo(right.Prefix);
        }
        else if (compareDomainDepth) {
            primaryComparison = CountDomainLabels(left.Value).CompareTo(CountDomainLabels(right.Value));
        }
        if (primaryComparison != 0) return primaryComparison;
        return System.StringComparer.Ordinal.Compare(left.Value, right.Value);
    }

    private static RoutingRuleItem Unwrap(object value) {
        var wrapped = value as System.Management.Automation.PSObject;
        return (RoutingRuleItem)(wrapped == null ? value : wrapped.BaseObject);
    }

    private static int CountDomainLabels(string value) {
        int labels = 1;
        for (int index = 0; index < value.Length; index++) {
            if (value[index] == '.') labels++;
        }
        return labels;
    }
}

public sealed class RoutingRuleGroupInput {
    public int Sequence { get; private set; }
    public string Id { get; private set; }
    public string Action { get; private set; }
    public int Extracted { get; private set; }
    public List<RoutingRuleItem> Items { get; private set; }

    public RoutingRuleGroupInput(int sequence, string id, string action, int extracted, object[] items) {
        Sequence = sequence;
        Id = id;
        Action = action;
        Extracted = extracted;
        Items = new List<RoutingRuleItem>(items.Length);
        foreach (object item in items) {
            var wrapped = item as System.Management.Automation.PSObject;
            Items.Add((RoutingRuleItem)(wrapped == null ? item : wrapped.BaseObject));
        }
    }
}

public sealed class RoutingRuleParseBatch {
    public object[] Items { get; private set; }
    public object[] Ignored { get; private set; }

    public RoutingRuleParseBatch(List<RoutingRuleItem> items, List<object> ignored) {
        Items = items.ToArray();
        Ignored = ignored.ToArray();
    }
}

public sealed class RoutingRuleMergeOutput {
    public System.Collections.Specialized.OrderedDictionary[] Groups { get; set; }
    public System.Collections.Specialized.OrderedDictionary[] ReportGroups { get; set; }
    public System.Collections.Specialized.OrderedDictionary[] RemovedSamples { get; set; }
    public int Extracted { get; set; }
    public int Retained { get; set; }
    public int Removed { get; set; }
    public int IntervalAdjusted { get; set; }
    public int IntervalSplitFragments { get; set; }
}

public static class RoutingRuleBatch {
    private const int MaxParsedCacheBytes = 268435456;
    private static readonly System.Text.Encoding StrictUtf8 = new System.Text.UTF8Encoding(false, true);
    private static readonly System.Text.RegularExpressions.Regex IPv4 = new System.Text.RegularExpressions.Regex(
        @"^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    private static readonly System.Text.RegularExpressions.Regex PortRange = new System.Text.RegularExpressions.Regex(
        @"^([0-9]{1,5})[:-]([0-9]{1,5})$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    private static readonly System.Text.RegularExpressions.Regex Domain = new System.Text.RegularExpressions.Regex(
        @"^[a-z0-9_\-]+(?:\.[a-z0-9_\-]+)*$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    private static readonly System.Text.RegularExpressions.Regex PlainDomain = new System.Text.RegularExpressions.Regex(
        @"^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$",
        System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    private static readonly System.Text.RegularExpressions.Regex Dnsmasq = new System.Text.RegularExpressions.Regex(
        @"^server=/([^/\s]+)/([^/\s]+)(?:\s+#.*)?$", System.Text.RegularExpressions.RegexOptions.CultureInvariant | System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    private static System.Management.Automation.PSObject NewIgnored(string source, int? line, string value, string reason) {
        System.Management.Automation.PSObject result = new System.Management.Automation.PSObject();
        result.Properties.Add(new System.Management.Automation.PSNoteProperty("Source", source));
        if (line.HasValue) result.Properties.Add(new System.Management.Automation.PSNoteProperty("Line", line.Value));
        result.Properties.Add(new System.Management.Automation.PSNoteProperty("Value", value));
        result.Properties.Add(new System.Management.Automation.PSNoteProperty("Reason", reason));
        return result;
    }

    private static string ReadBoundedString(System.IO.BinaryReader reader, int maxBytes, int maxChars) {
        int byteCount = 0;
        int shift = 0;
        bool complete = false;
        for (int index = 0; index < 5; index++) {
            byte current = reader.ReadByte();
            if (index == 4 && current > 0x07) throw new System.IO.InvalidDataException("Parsed cache string length is invalid.");
            byteCount |= (current & 0x7F) << shift;
            if ((current & 0x80) == 0) { complete = true; break; }
            shift += 7;
        }
        if (!complete || byteCount < 0 || byteCount > maxBytes || byteCount > reader.BaseStream.Length - reader.BaseStream.Position)
            throw new System.IO.InvalidDataException("Parsed cache string length is invalid.");
        byte[] encoded = reader.ReadBytes(byteCount);
        if (encoded.Length != byteCount) throw new System.IO.EndOfStreamException();
        string value = StrictUtf8.GetString(encoded);
        if (value.Length > maxChars) throw new System.IO.InvalidDataException("Parsed cache string is too long.");
        return value;
    }

    private static void WriteBoundedString(System.IO.BinaryWriter writer, string value, int maxBytes, int maxChars) {
        if (value == null) value = String.Empty;
        if (value.Length > maxChars) throw new System.IO.InvalidDataException("Parsed cache string is too long.");
        byte[] encoded = StrictUtf8.GetBytes(value);
        if (encoded.Length > maxBytes) throw new System.IO.InvalidDataException("Parsed cache string is too long.");
        int remaining = encoded.Length;
        while (remaining >= 0x80) {
            writer.Write((byte)((remaining & 0x7F) | 0x80));
            remaining >>= 7;
        }
        writer.Write((byte)remaining);
        writer.Write(encoded);
    }

    private static bool IsAllowedKind(string kind) {
        return kind == "domain" || kind == "domain_suffix" || kind == "domain_regex" || kind == "ip_cidr" || kind == "port" ||
            kind == "port_range" || kind == "source_port" || kind == "source_port_range";
    }

    private static bool IsCanonicalCachedTextValue(string kind, string value) {
        if (String.IsNullOrEmpty(value)) return false;
        if (kind == "domain_regex") return value.StartsWith("(?i)^", StringComparison.Ordinal) && value.EndsWith("$", StringComparison.Ordinal);
        if (kind == "domain" || kind == "domain_suffix") {
            if (value.Length > 253 || !Domain.IsMatch(value)) return false;
            foreach (string label in value.Split('.')) if (label.Length > 63) return false;
            return String.Equals(value, value.ToLowerInvariant(), StringComparison.Ordinal);
        }
        if (kind == "port" || kind == "source_port") {
            int number;
            return Int32.TryParse(value, System.Globalization.NumberStyles.Integer,
                System.Globalization.CultureInfo.CurrentCulture, out number) && number >= 1 && number <= 65535 &&
                String.Equals(value, number.ToString(System.Globalization.CultureInfo.CurrentCulture), StringComparison.Ordinal);
        }
        if (kind == "port_range" || kind == "source_port_range") {
            System.Text.RegularExpressions.Match match = PortRange.Match(value);
            int start, end;
            return match.Success && Int32.TryParse(match.Groups[1].Value, out start) && Int32.TryParse(match.Groups[2].Value, out end) &&
                start >= 1 && end <= 65535 && start <= end &&
                String.Equals(value, start.ToString(System.Globalization.CultureInfo.CurrentCulture) + ":" +
                    end.ToString(System.Globalization.CultureInfo.CurrentCulture), StringComparison.Ordinal);
        }
        return false;
    }

    private static bool IsCanonicalCachedIgnored(string format, string tag, string source, string value, string reason, bool hasLine) {
        if (!hasLine || !String.Equals(source, tag, StringComparison.Ordinal)) return false;
        return String.Equals(format, "clash-yaml", StringComparison.Ordinal) &&
            String.Equals(reason, "ipv6-rejected-by-core", StringComparison.Ordinal) &&
            value.StartsWith("IP-CIDR6,", StringComparison.OrdinalIgnoreCase);
    }

    private static RoutingRuleItem NewItem(string kind, string value, int sequence, string group, string action, string source,
        ulong network, int prefix, ulong mask) {
        return new RoutingRuleItem(kind, value, sequence, group, action, source, network, prefix, mask);
    }

    private static bool TryIPv4Cidr(string value, out string normalized, out ulong network, out int prefix, out ulong mask) {
        normalized = null;
        network = 0;
        prefix = 0;
        mask = 0;
        string[] parts = value.Split(new char[] { '/' }, 2);
        if (!IPv4.IsMatch(parts[0])) return false;
        System.Net.IPAddress address;
        if (!System.Net.IPAddress.TryParse(parts[0], out address) ||
            address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return false;
        prefix = 32;
        if (parts.Length == 2 && (!System.Text.RegularExpressions.Regex.IsMatch(parts[1], @"^[0-9]+$", System.Text.RegularExpressions.RegexOptions.CultureInvariant) ||
            !Int32.TryParse(parts[1], out prefix) || prefix < 0 || prefix > 32)) return false;
        byte[] bytes = address.GetAddressBytes();
        ulong valueBits = ((ulong)bytes[0] << 24) | ((ulong)bytes[1] << 16) | ((ulong)bytes[2] << 8) | bytes[3];
        mask = prefix == 0 ? 0UL : (0xFFFFFFFFUL >> (32 - prefix)) << (32 - prefix);
        network = valueBits & mask;
        normalized = String.Format(System.Globalization.CultureInfo.InvariantCulture, "{0}.{1}.{2}.{3}/{4}",
            (network >> 24) & 255, (network >> 16) & 255, (network >> 8) & 255, network & 255, prefix);
        return true;
    }

    private static bool IsCanonicalIPv4Item(RoutingRuleItem item) {
        if (item == null || item.Kind != "ip_cidr") return false;
        string normalized;
        ulong network, mask;
        int prefix;
        return TryIPv4Cidr(item.Value, out normalized, out network, out prefix, out mask) &&
            String.Equals(normalized, item.Value, StringComparison.Ordinal) && item.Network == network &&
            item.Prefix == prefix && item.Mask == mask;
    }

    private static void AddTextValue(string kind, string rawValue, int sequence, string group, string action, string source,
        List<RoutingRuleItem> items, List<object> ignored) {
        string value = (rawValue ?? String.Empty).Trim().TrimStart('\uFEFF');
        if (value.Length == 0) return;
        if (kind == "ip_cidr") {
            string normalized;
            ulong network, mask;
            int prefix;
            if (TryIPv4Cidr(value, out normalized, out network, out prefix, out mask))
                items.Add(NewItem(kind, normalized, sequence, group, action, source, network, prefix, mask));
            else ignored.Add(NewIgnored(source, null, value, "invalid-or-ipv6"));
            return;
        }
        if (kind == "port" || kind == "source_port") {
            int number;
            if (Int32.TryParse(value, out number) && number >= 1 && number <= 65535)
                items.Add(NewItem(kind, number.ToString(System.Globalization.CultureInfo.CurrentCulture), sequence, group, action, source, 0, 0, 0));
            else ignored.Add(NewIgnored(source, null, value, "invalid-port"));
            return;
        }
        if (kind == "port_range" || kind == "source_port_range") {
            System.Text.RegularExpressions.Match match = PortRange.Match(value);
            if (match.Success) {
                int start, end;
                if (Int32.TryParse(match.Groups[1].Value, out start) && Int32.TryParse(match.Groups[2].Value, out end) &&
                    start >= 1 && end <= 65535 && start <= end) {
                    items.Add(NewItem(kind, start.ToString(System.Globalization.CultureInfo.CurrentCulture) + ":" +
                        end.ToString(System.Globalization.CultureInfo.CurrentCulture), sequence, group, action, source, 0, 0, 0));
                    return;
                }
            }
            ignored.Add(NewIgnored(source, null, value, "invalid-port-range"));
            return;
        }
        if (kind == "domain_keyword" || kind == "domain_regex") return;
        string normalizedDomain = value.TrimEnd('.').ToLowerInvariant();
        if (normalizedDomain.StartsWith(".", StringComparison.Ordinal)) normalizedDomain = normalizedDomain.Substring(1);
        bool invalid = normalizedDomain.Length > 253 || !Domain.IsMatch(normalizedDomain);
        if (!invalid) {
            foreach (string label in normalizedDomain.Split('.')) if (label.Length > 63) { invalid = true; break; }
        }
        if (invalid) throw new FormatException("无效域名：" + value + "（来源：" + source + "）");
        if (normalizedDomain.Length > 0) items.Add(NewItem(kind, normalizedDomain, sequence, group, action, source, 0, 0, 0));
    }

    public static RoutingRuleParseBatch ParseTextValues(string kind, string[] rawValues, int sequence, string group, string action, string source) {
        List<RoutingRuleItem> items = new List<RoutingRuleItem>();
        List<object> ignored = new List<object>();
        if (rawValues != null) foreach (string rawValue in rawValues)
            AddTextValue(kind, rawValue, sequence, group, action, source, items, ignored);
        return new RoutingRuleParseBatch(items, ignored);
    }

    public static RoutingRuleParseBatch ParsePlainLines(string[] lines, int sequence, string group, string action, string source) {
        List<RoutingRuleItem> items = new List<RoutingRuleItem>();
        List<object> ignored = new List<object>();
        if (lines == null) lines = new string[0];
        for (int index = 0; index < lines.Length; index++) {
            string token = (lines[index] ?? String.Empty).Trim().TrimStart('\uFEFF');
            if (token.Length == 0 || token.StartsWith("#", StringComparison.Ordinal) || token.StartsWith(";", StringComparison.Ordinal) ||
                token.StartsWith("//", StringComparison.Ordinal)) continue;
            string normalized;
            ulong network, mask;
            int prefix;
            if (TryIPv4Cidr(token, out normalized, out network, out prefix, out mask)) {
                items.Add(NewItem("ip_cidr", normalized, sequence, group, action, source, network, prefix, mask));
                continue;
            }
            if (System.Text.RegularExpressions.Regex.IsMatch(token, @"^([0-9]{1,5})$", System.Text.RegularExpressions.RegexOptions.CultureInvariant)) {
                AddTextValue("port", token, sequence, group, action, source, items, ignored);
                continue;
            }
            if (PortRange.IsMatch(token)) {
                AddTextValue("port_range", token, sequence, group, action, source, items, ignored);
                continue;
            }
            if (PlainDomain.IsMatch(token)) {
                AddTextValue("domain", token, sequence, group, action, source, items, ignored);
                continue;
            }
            ignored.Add(NewIgnored(source, index + 1, token, "unsupported"));
        }
        return new RoutingRuleParseBatch(items, ignored);
    }

    private static readonly System.Text.RegularExpressions.Regex AdGuardAnchor = new System.Text.RegularExpressions.Regex(
        @"^\|\|([A-Za-z0-9_.-]+)\^$", System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    public static string[] ReadAdGuardDnsExceptions(string[] lines) {
        var exceptions = new HashSet<string>(StringComparer.Ordinal);
        foreach (string line in lines) {
            string token = line.Trim();
            if (!token.StartsWith("@@", StringComparison.Ordinal)) continue;
            var match = AdGuardAnchor.Match(token.Substring(2));
            if (!match.Success) throw new FormatException("Unsupported AdGuard DNS exception: " + token);
            exceptions.Add(match.Groups[1].Value.TrimEnd('.').ToLowerInvariant());
        }
        return new List<string>(exceptions).ToArray();
    }

    public static RoutingRuleParseBatch ParseAdGuardDnsLines(string[] lines, string[] exceptions,
        Func<string, string> remainingSuffix, int sequence, string group, string action, string source) {
        var except = new HashSet<string>(exceptions, StringComparer.Ordinal);
        var partial = new HashSet<string>(StringComparer.Ordinal);
        foreach (string exception in exceptions) {
            int dot = exception.IndexOf('.');
            while (dot >= 0) {
                partial.Add(exception.Substring(dot + 1));
                dot = exception.IndexOf('.', dot + 1);
            }
        }
        var items = new List<RoutingRuleItem>();
        var ignored = new List<object>();
        foreach (string line in lines) {
            string token = line.Trim();
            if (token.Length == 0 || token.StartsWith("!", StringComparison.Ordinal) ||
                token.StartsWith("#", StringComparison.Ordinal) || token.StartsWith("@@", StringComparison.Ordinal) ||
                token == "[Adblock Plus 2.0]") continue;
            var anchor = AdGuardAnchor.Match(token);
            if (!anchor.Success) continue;
            string value = anchor.Groups[1].Value.TrimEnd('.').ToLowerInvariant();
            bool excluded = except.Contains(value);
            for (int dot = value.IndexOf('.'); !excluded && dot >= 0; dot = value.IndexOf('.', dot + 1))
                excluded = except.Contains(value.Substring(dot + 1));
            if (excluded) continue;
            if (IPv4.IsMatch(value)) {
                AddTextValue("ip_cidr", value, sequence, group, action, source, items, ignored);
                continue;
            }
            if (value.IndexOf('.') < 0) continue;
            if (partial.Contains(value)) {
                string pattern = remainingSuffix(value);
                if (!String.IsNullOrEmpty(pattern)) items.Add(NewItem("domain_regex", pattern, sequence, group, action, source, 0, 0, 0));
            } else {
                AddTextValue("domain_suffix", value, sequence, group, action, source, items, ignored);
            }
        }
        return new RoutingRuleParseBatch(items, ignored);
    }

    public static RoutingRuleParseBatch ParseDnsmasqLines(string[] lines, int sequence, string group, string action, string source) {
        List<string> suffixes = new List<string>();
        List<object> ignored = new List<object>();
        if (lines == null) lines = new string[0];
        for (int index = 0; index < lines.Length; index++) {
            string token = (lines[index] ?? String.Empty).Trim().TrimStart('\uFEFF');
            if (token.Length == 0 || token.StartsWith("#", StringComparison.Ordinal)) continue;
            System.Text.RegularExpressions.Match match = Dnsmasq.Match(token);
            if (match.Success) suffixes.Add(match.Groups[1].Value.TrimStart('.'));
            else ignored.Add(NewIgnored(source, index + 1, token, "invalid-dnsmasq-line"));
        }
        List<RoutingRuleItem> items = new List<RoutingRuleItem>();
        foreach (string suffix in suffixes) AddTextValue("domain_suffix", suffix, sequence, group, action, source, items, ignored);
        return new RoutingRuleParseBatch(items, ignored);
    }

    public static RoutingRuleItem[] Recontextualize(object[] sourceItems, int sequence, string group, string action, string source) {
        if (sourceItems == null) return new RoutingRuleItem[0];
        RoutingRuleItem[] result = new RoutingRuleItem[sourceItems.Length];
        for (int index = 0; index < sourceItems.Length; index++) {
            var wrapped = sourceItems[index] as System.Management.Automation.PSObject;
            RoutingRuleItem item = (RoutingRuleItem)(wrapped == null ? sourceItems[index] : wrapped.BaseObject);
            result[index] = new RoutingRuleItem(item.Kind, item.Value, sequence, group, action, source, item.Network, item.Prefix, item.Mask);
        }
        return result;
    }

    public static RoutingRuleParseBatch ReadParsedCache(string path, string sourceHash, string parserFingerprint, string format, string tag) {
        try {
            System.IO.FileInfo fileInfo = new System.IO.FileInfo(path);
            if (!fileInfo.Exists || fileInfo.Length < 64 || fileInfo.Length > MaxParsedCacheBytes) return null;
            byte[] bytes = System.IO.File.ReadAllBytes(path);
            if (bytes.Length < 64) return null;
            int payloadLength = bytes.Length - 32;
            byte[] payload = new byte[payloadLength];
            Buffer.BlockCopy(bytes, 0, payload, 0, payloadLength);
            byte[] expected = new byte[32];
            Buffer.BlockCopy(bytes, payloadLength, expected, 0, expected.Length);
            byte[] actual;
            using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create()) actual = sha.ComputeHash(payload);
            int difference = 0;
            for (int index = 0; index < expected.Length; index++) difference |= expected[index] ^ actual[index];
            if (difference != 0) return null;
            using (System.IO.MemoryStream stream = new System.IO.MemoryStream(payload, false))
            using (System.IO.BinaryReader reader = new System.IO.BinaryReader(stream, System.Text.Encoding.UTF8)) {
                if (ReadBoundedString(reader, 8, 8) != "RRPC" || reader.ReadInt32() != 2) return null;
                if (ReadBoundedString(reader, 128, 128) != sourceHash || ReadBoundedString(reader, 128, 128) != parserFingerprint ||
                    ReadBoundedString(reader, 128, 128) != format || ReadBoundedString(reader, 512, 256) != tag) return null;
                int itemCount = reader.ReadInt32();
                if (itemCount < 1 || itemCount > 10000000) return null;
                List<RoutingRuleItem> items = new List<RoutingRuleItem>(itemCount);
                for (int index = 0; index < itemCount; index++) {
                    string kind = ReadBoundedString(reader, 64, 64);
                    string value = ReadBoundedString(reader, 4096, 4096);
                    ulong network = reader.ReadUInt64();
                    int prefix = reader.ReadInt32();
                    ulong mask = reader.ReadUInt64();
                    if (!IsAllowedKind(kind) || value.Length == 0) return null;
                    if (kind == "ip_cidr") {
                        string normalized;
                        ulong expectedNetwork, expectedMask;
                        int expectedPrefix;
                        if (!TryIPv4Cidr(value, out normalized, out expectedNetwork, out expectedPrefix, out expectedMask) ||
                            normalized != value || network != expectedNetwork || prefix != expectedPrefix || mask != expectedMask) return null;
                    }
                    else if (network != 0 || prefix != 0 || mask != 0 || !IsCanonicalCachedTextValue(kind, value)) return null;
                    items.Add(new RoutingRuleItem(kind, value, 0, "validation", "direct", tag, network, prefix, mask));
                }
                int ignoredCount = reader.ReadInt32();
                if (ignoredCount < 0 || ignoredCount > 10000000) return null;
                List<object> ignored = new List<object>(ignoredCount);
                for (int index = 0; index < ignoredCount; index++) {
                    bool hasLine = reader.ReadBoolean();
                    int line = hasLine ? reader.ReadInt32() : 0;
                    if (hasLine && line < 1) return null;
                    string source = ReadBoundedString(reader, 4096, 2048);
                    string value = ReadBoundedString(reader, 1048576, 1048576);
                    string reason = ReadBoundedString(reader, 1024, 512);
                    if (String.IsNullOrEmpty(source) || String.IsNullOrEmpty(reason) ||
                        !IsCanonicalCachedIgnored(format, tag, source, value, reason, hasLine)) return null;
                    ignored.Add(NewIgnored(source, hasLine ? (int?)line : null, value, reason));
                }
                if (stream.Position != stream.Length) return null;
                return new RoutingRuleParseBatch(items, ignored);
            }
        }
        catch (System.IO.FileNotFoundException) { return null; }
        catch (System.IO.DirectoryNotFoundException) { return null; }
        catch (System.IO.IOException) { return null; }
        catch (System.Exception) { return null; }
    }

    public static void WriteParsedCache(string path, string sourceHash, string parserFingerprint, string format, string tag,
        object[] rawItems, object[] rawIgnored) {
        string temporaryPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try {
            List<RoutingRuleItem> items = new List<RoutingRuleItem>(rawItems == null ? 0 : rawItems.Length);
            if (rawItems != null) foreach (object raw in rawItems) {
                var wrapped = raw as System.Management.Automation.PSObject;
                RoutingRuleItem item = (RoutingRuleItem)(wrapped == null ? raw : wrapped.BaseObject);
                if (item == null || !IsAllowedKind(item.Kind) || String.IsNullOrEmpty(item.Value) ||
                    (item.Kind == "ip_cidr" ? !IsCanonicalIPv4Item(item) :
                        item.Network != 0 || item.Prefix != 0 || item.Mask != 0 || !IsCanonicalCachedTextValue(item.Kind, item.Value)))
                    throw new System.IO.InvalidDataException("Parsed cache item is not canonical.");
                items.Add(item);
            }
            using (System.IO.MemoryStream stream = new System.IO.MemoryStream())
            using (System.IO.BinaryWriter writer = new System.IO.BinaryWriter(stream, System.Text.Encoding.UTF8)) {
                WriteBoundedString(writer, "RRPC", 8, 8);
                writer.Write(2);
                WriteBoundedString(writer, sourceHash, 128, 128);
                WriteBoundedString(writer, parserFingerprint, 128, 128);
                WriteBoundedString(writer, format, 128, 128);
                WriteBoundedString(writer, tag, 512, 256);
                writer.Write(items.Count);
                foreach (RoutingRuleItem item in items) {
                    if (!IsAllowedKind(item.Kind)) throw new System.IO.InvalidDataException("Unsupported parsed cache kind.");
                    WriteBoundedString(writer, item.Kind, 64, 64);
                    WriteBoundedString(writer, item.Value, 4096, 4096);
                    writer.Write(item.Network);
                    writer.Write(item.Prefix);
                    writer.Write(item.Mask);
                }
                writer.Write(rawIgnored == null ? 0 : rawIgnored.Length);
                if (rawIgnored != null) foreach (object raw in rawIgnored) {
                    var wrapped = raw as System.Management.Automation.PSObject;
                    System.Management.Automation.PSObject item = wrapped;
                    if (item == null) item = new System.Management.Automation.PSObject(raw);
                    System.Management.Automation.PSPropertyInfo lineProperty = item.Properties["Line"];
                    System.Management.Automation.PSPropertyInfo sourceProperty = item.Properties["Source"];
                    System.Management.Automation.PSPropertyInfo valueProperty = item.Properties["Value"];
                    System.Management.Automation.PSPropertyInfo reasonProperty = item.Properties["Reason"];
                    bool hasLine = lineProperty != null && lineProperty.Value != null;
                    writer.Write(hasLine);
                    if (hasLine) writer.Write(Convert.ToInt32(lineProperty.Value, System.Globalization.CultureInfo.InvariantCulture));
                    WriteBoundedString(writer, sourceProperty == null ? tag : Convert.ToString(sourceProperty.Value, System.Globalization.CultureInfo.InvariantCulture), 4096, 2048);
                    WriteBoundedString(writer, valueProperty == null ? String.Empty : Convert.ToString(valueProperty.Value, System.Globalization.CultureInfo.InvariantCulture), 1048576, 1048576);
                    WriteBoundedString(writer, reasonProperty == null ? String.Empty : Convert.ToString(reasonProperty.Value, System.Globalization.CultureInfo.InvariantCulture), 1024, 512);
                }
                writer.Flush();
                byte[] payload = stream.ToArray();
                byte[] digest;
                using (System.Security.Cryptography.SHA256 sha = System.Security.Cryptography.SHA256.Create()) digest = sha.ComputeHash(payload);
                byte[] complete = new byte[payload.Length + digest.Length];
                Buffer.BlockCopy(payload, 0, complete, 0, payload.Length);
                Buffer.BlockCopy(digest, 0, complete, payload.Length, digest.Length);
                if (complete.Length > MaxParsedCacheBytes) throw new System.IO.InvalidDataException("Parsed cache exceeds the size limit.");
                string parent = System.IO.Path.GetDirectoryName(path);
                if (!String.IsNullOrEmpty(parent)) System.IO.Directory.CreateDirectory(parent);
                System.IO.File.WriteAllBytes(temporaryPath, complete);
            }
            if (System.IO.File.Exists(path)) System.IO.File.Replace(temporaryPath, path, null);
            else System.IO.File.Move(temporaryPath, path);
        }
        finally {
            if (System.IO.File.Exists(temporaryPath)) System.IO.File.Delete(temporaryPath);
        }
    }
}

public static class RoutingRuleMergeEngine {
    private sealed class CidrKey : IEquatable<CidrKey> {
        public readonly int Prefix;
        public readonly ulong Network;
        public CidrKey(int prefix, ulong network) { Prefix = prefix; Network = network; }
        public bool Equals(CidrKey other) { return other != null && Prefix == other.Prefix && Network == other.Network; }
        public override bool Equals(object value) { return Equals(value as CidrKey); }
        public override int GetHashCode() { unchecked { return (Prefix * 397) ^ Network.GetHashCode(); } }
    }
    private sealed class PortInterval {
        public int Start, End;
        public RoutingRuleItem Item;
        public PortInterval(int start, int end, RoutingRuleItem item) { Start = start; End = end; Item = item; }
    }
    private sealed class Segment {
        public int Start, End;
        public Segment(int start, int end) { Start = start; End = end; }
    }
    private static int CountLabels(string value) {
        int count = 1;
        for (int index = 0; index < value.Length; index++) if (value[index] == '.') count++;
        return count;
    }
    private static string ExactKey(RoutingRuleItem item) { return item.Kind + "\0" + item.Value; }
    private static bool TryFindDomainSuffix(Dictionary<string, RoutingRuleItem> suffixes, string value, out RoutingRuleItem winner) {
        for (int index = 0; index <= value.Length; index++) {
            if (index != 0 && value[index - 1] != '.') continue;
            if (suffixes.TryGetValue(value.Substring(index), out winner)) return true;
        }
        winner = null;
        return false;
    }
    private static System.Collections.Specialized.OrderedDictionary Dictionary(params object[] pairs) {
        System.Collections.Specialized.OrderedDictionary result = new System.Collections.Specialized.OrderedDictionary(StringComparer.Ordinal);
        for (int index = 0; index < pairs.Length; index += 2) result.Add((string)pairs[index], pairs[index + 1]);
        return result;
    }
    private static string[] SortedUniqueStrings(List<string> values) {
        HashSet<string> set = new HashSet<string>(values, StringComparer.Ordinal);
        string[] result = new string[set.Count];
        set.CopyTo(result);
        Array.Sort(result, StringComparer.Ordinal);
        return result;
    }
    private static int[] SortedUniqueInts(List<int> values) {
        HashSet<int> set = new HashSet<int>(values);
        int[] result = new int[set.Count];
        set.CopyTo(result);
        Array.Sort(result);
        return result;
    }
    private static string GroupTag(string id) {
        return "routing-" + System.Text.RegularExpressions.Regex.Replace(id, "[^A-Za-z0-9_-]", "-");
    }
    private static int[] PortBounds(RoutingRuleItem candidate) {
        if (candidate.Kind == "port" || candidate.Kind == "source_port") {
            int value = Int32.Parse(candidate.Value, System.Globalization.CultureInfo.InvariantCulture);
            return new int[] { value, value };
        }
        string[] parts = candidate.Value.Split(':');
        return new int[] { Int32.Parse(parts[0], System.Globalization.CultureInfo.InvariantCulture), Int32.Parse(parts[1], System.Globalization.CultureInfo.InvariantCulture) };
    }

    public static RoutingRuleMergeOutput Merge(RoutingRuleGroupInput[] groups, int sampleLimit) {
        System.Collections.Generic.Dictionary<string, RoutingRuleItem> exactIndex = new System.Collections.Generic.Dictionary<string, RoutingRuleItem>(StringComparer.Ordinal);
        System.Collections.Generic.Dictionary<CidrKey, RoutingRuleItem> cidrIndex = new System.Collections.Generic.Dictionary<CidrKey, RoutingRuleItem>();
        System.Collections.Generic.Dictionary<string, RoutingRuleItem> domainSuffixIndex = new System.Collections.Generic.Dictionary<string, RoutingRuleItem>(StringComparer.Ordinal);
        System.Collections.Generic.Dictionary<string, List<PortInterval>> portIntervals = new System.Collections.Generic.Dictionary<string, List<PortInterval>>(StringComparer.Ordinal);
        portIntervals.Add("port", new List<PortInterval>());
        portIntervals.Add("source_port", new List<PortInterval>());
        List<List<RoutingRuleItem>> retainedByGroup = new List<List<RoutingRuleItem>>(groups.Length);
        List<System.Collections.Specialized.OrderedDictionary> removedSamples = new List<System.Collections.Specialized.OrderedDictionary>();
        int removedCount = 0, intervalAdjustedCount = 0, intervalSplitFragments = 0, extractedCount = 0;

        foreach (RoutingRuleGroupInput group in groups) {
            extractedCount += group.Extracted;
            List<RoutingRuleItem> retained = new List<RoutingRuleItem>();
            retainedByGroup.Add(retained);
            List<RoutingRuleItem> cidrItems = new List<RoutingRuleItem>();
            List<RoutingRuleItem> suffixItems = new List<RoutingRuleItem>();
            List<RoutingRuleItem> otherItems = new List<RoutingRuleItem>();
            foreach (RoutingRuleItem item in group.Items) {
                if (item.Kind == "ip_cidr") cidrItems.Add(item);
                else if (item.Kind == "domain_suffix") suffixItems.Add(item);
                else otherItems.Add(item);
            }
            RoutingRuleItem[] sortedCidrs = cidrItems.ToArray();
            Array.Sort(sortedCidrs, delegate(RoutingRuleItem left, RoutingRuleItem right) {
                int comparison = left.Prefix.CompareTo(right.Prefix);
                return comparison != 0 ? comparison : StringComparer.Ordinal.Compare(left.Value, right.Value);
            });
            RoutingRuleItem[] sortedSuffixes = suffixItems.ToArray();
            Array.Sort(sortedSuffixes, delegate(RoutingRuleItem left, RoutingRuleItem right) {
                int comparison = CountLabels(left.Value).CompareTo(CountLabels(right.Value));
                return comparison != 0 ? comparison : StringComparer.Ordinal.Compare(left.Value, right.Value);
            });
            List<RoutingRuleItem> candidates = new List<RoutingRuleItem>(sortedCidrs.Length + sortedSuffixes.Length + otherItems.Count);
            candidates.AddRange(sortedCidrs);
            candidates.AddRange(sortedSuffixes);
            candidates.AddRange(otherItems);

            foreach (RoutingRuleItem candidate in candidates) {
                if (candidate.Kind == "port" || candidate.Kind == "port_range" || candidate.Kind == "source_port" || candidate.Kind == "source_port_range") {
                    string family = candidate.Kind.StartsWith("source_", StringComparison.Ordinal) ? "source_port" : "port";
                    int[] bounds = PortBounds(candidate);
                    int candidateStart = bounds[0], candidateEnd = bounds[1];
                    List<Segment> segments = new List<Segment>();
                    segments.Add(new Segment(candidateStart, candidateEnd));
                    RoutingRuleItem overlapWinner = null;
                    foreach (PortInterval covered in portIntervals[family]) {
                        List<Segment> nextSegments = new List<Segment>();
                        foreach (Segment segment in segments) {
                            if (covered.End < segment.Start || covered.Start > segment.End) {
                                nextSegments.Add(segment);
                                continue;
                            }
                            if (overlapWinner == null) overlapWinner = covered.Item;
                            if (covered.Start > segment.Start) nextSegments.Add(new Segment(segment.Start, covered.Start - 1));
                            if (covered.End < segment.End) nextSegments.Add(new Segment(covered.End + 1, segment.End));
                        }
                        segments = nextSegments;
                        if (segments.Count == 0) break;
                    }
                    if (segments.Count == 0) {
                        removedCount++;
                        if (removedSamples.Count < sampleLimit) removedSamples.Add(Dictionary(
                            "Kind", candidate.Kind, "Value", candidate.Value, "RemovedGroup", candidate.Group, "RemovedAction", candidate.Action,
                            "KeptGroup", overlapWinner.Group, "KeptAction", overlapWinner.Action, "Reason", "covered"));
                        continue;
                    }
                    bool unchanged = segments.Count == 1 && segments[0].Start == candidateStart && segments[0].End == candidateEnd;
                    if (!unchanged) { intervalAdjustedCount++; intervalSplitFragments += segments.Count - 1; }
                    foreach (Segment segment in segments) {
                        string segmentKind = segment.Start == segment.End ? family : family + "_range";
                        string segmentValue = segment.Start == segment.End
                            ? segment.Start.ToString(System.Globalization.CultureInfo.CurrentCulture)
                            : segment.Start.ToString(System.Globalization.CultureInfo.CurrentCulture) + ":" + segment.End.ToString(System.Globalization.CultureInfo.CurrentCulture);
                        RoutingRuleItem segmentItem = new RoutingRuleItem(segmentKind, segmentValue, candidate.Sequence, candidate.Group,
                            candidate.Action, candidate.Source, 0, 0, 0);
                        retained.Add(segmentItem);
                        portIntervals[family].Add(new PortInterval(segment.Start, segment.End, segmentItem));
                    }
                    continue;
                }

                RoutingRuleItem winner = null;
                if (!exactIndex.TryGetValue(ExactKey(candidate), out winner)) {
                    if (candidate.Kind == "ip_cidr") {
                        for (int prefix = 0; prefix <= candidate.Prefix; prefix++) {
                            ulong mask = prefix == 0 ? 0UL : (0xFFFFFFFFUL >> (32 - prefix)) << (32 - prefix);
                            if (cidrIndex.TryGetValue(new CidrKey(prefix, candidate.Network & mask), out winner)) break;
                        }
                    }
                    else if (candidate.Kind == "domain" || candidate.Kind == "domain_suffix") {
                        TryFindDomainSuffix(domainSuffixIndex, candidate.Value, out winner);
                    }
                }
                if (winner != null) {
                    removedCount++;
                    if (removedSamples.Count < sampleLimit) removedSamples.Add(Dictionary(
                        "Kind", candidate.Kind, "Value", candidate.Value, "RemovedGroup", candidate.Group, "RemovedAction", candidate.Action,
                        "KeptGroup", winner.Group, "KeptAction", winner.Action,
                        "Reason", String.Equals(candidate.Value, winner.Value, StringComparison.Ordinal) ? "duplicate" : "covered"));
                    continue;
                }
                retained.Add(candidate);
                exactIndex[ExactKey(candidate)] = candidate;
                if (candidate.Kind == "ip_cidr") cidrIndex[new CidrKey(candidate.Prefix, candidate.Network)] = candidate;
                else if (candidate.Kind == "domain_suffix") domainSuffixIndex[candidate.Value] = candidate;
            }
        }

        List<System.Collections.Specialized.OrderedDictionary> outputGroups = new List<System.Collections.Specialized.OrderedDictionary>();
        List<System.Collections.Specialized.OrderedDictionary> reportGroups = new List<System.Collections.Specialized.OrderedDictionary>();
        int retainedCount = 0;
        for (int groupIndex = 0; groupIndex < groups.Length; groupIndex++) {
            RoutingRuleGroupInput group = groups[groupIndex];
            List<RoutingRuleItem> items = retainedByGroup[groupIndex];
            List<System.Collections.Specialized.OrderedDictionary> rules = new List<System.Collections.Specialized.OrderedDictionary>();
            List<string> domain = new List<string>(), domainSuffix = new List<string>(), domainRegex = new List<string>(), ipCidr = new List<string>();
            List<int> port = new List<int>(), sourcePort = new List<int>();
            List<string> portRange = new List<string>(), sourcePortRange = new List<string>();
            bool hasDomain = false;
            foreach (RoutingRuleItem item in items) {
                switch (item.Kind) {
                    case "domain": domain.Add(item.Value); hasDomain = true; break;
                    case "domain_suffix": domainSuffix.Add(item.Value); hasDomain = true; break;
                    case "domain_regex": domainRegex.Add(item.Value); hasDomain = true; break;
                    case "ip_cidr": ipCidr.Add(item.Value); break;
                    case "port": port.Add(Int32.Parse(item.Value, System.Globalization.CultureInfo.InvariantCulture)); break;
                    case "port_range": portRange.Add(item.Value); break;
                    case "source_port": sourcePort.Add(Int32.Parse(item.Value, System.Globalization.CultureInfo.InvariantCulture)); break;
                    case "source_port_range": sourcePortRange.Add(item.Value); break;
                }
            }
            System.Collections.Specialized.OrderedDictionary domainRule = new System.Collections.Specialized.OrderedDictionary(StringComparer.Ordinal);
            if (domain.Count > 0) domainRule.Add("domain", SortedUniqueStrings(domain));
            if (domainSuffix.Count > 0) domainRule.Add("domain_suffix", SortedUniqueStrings(domainSuffix));
            if (domainRegex.Count > 0) domainRule.Add("domain_regex", SortedUniqueStrings(domainRegex));
            if (domainRule.Count > 0) rules.Add(domainRule);
            if (ipCidr.Count > 0) rules.Add(Dictionary("ip_cidr", SortedUniqueStrings(ipCidr)));
            System.Collections.Specialized.OrderedDictionary portRule = new System.Collections.Specialized.OrderedDictionary(StringComparer.Ordinal);
            if (port.Count > 0) portRule.Add("port", SortedUniqueInts(port));
            if (portRange.Count > 0) portRule.Add("port_range", SortedUniqueStrings(portRange));
            if (portRule.Count > 0) rules.Add(portRule);
            System.Collections.Specialized.OrderedDictionary sourcePortRule = new System.Collections.Specialized.OrderedDictionary(StringComparer.Ordinal);
            if (sourcePort.Count > 0) sourcePortRule.Add("source_port", SortedUniqueInts(sourcePort));
            if (sourcePortRange.Count > 0) sourcePortRule.Add("source_port_range", SortedUniqueStrings(sourcePortRange));
            if (sourcePortRule.Count > 0) rules.Add(sourcePortRule);
            reportGroups.Add(Dictionary("sequence", group.Sequence, "id", group.Id, "action", group.Action,
                "extracted", group.Extracted, "retained", items.Count));
            if (items.Count == 0) continue;
            outputGroups.Add(Dictionary("tag", GroupTag(group.Id), "sequence", group.Sequence, "id", group.Id,
                "action", group.Action, "has_domain", hasDomain, "rules", rules.ToArray()));
            retainedCount += items.Count;
        }

        return new RoutingRuleMergeOutput {
            Groups = outputGroups.ToArray(),
            ReportGroups = reportGroups.ToArray(),
            RemovedSamples = removedSamples.ToArray(),
            Extracted = extractedCount,
            Retained = retainedCount,
            Removed = removedCount,
            IntervalAdjusted = intervalAdjustedCount,
            IntervalSplitFragments = intervalSplitFragments
        };
    }
}
