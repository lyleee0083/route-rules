using System;
using System.Collections.Generic;
using System.Net;
using System.Numerics;
using System.Text.RegularExpressions;

namespace SingBoxSameType {
    public sealed class DomainNode {
        public bool Exact, Suffix;
        public readonly SortedDictionary<string, DomainNode> Children = new SortedDictionary<string, DomainNode>(StringComparer.Ordinal);
    }
    public sealed class LabelNode {
        public bool Terminal;
        public readonly SortedDictionary<char, LabelNode> Children = new SortedDictionary<char, LabelNode>();
    }
    public sealed class DomainCompiler {
        private readonly DomainNode root = new DomainNode();
        private const string Alphabet = "-0123456789_abcdefghijklmnopqrstuvwxyz";
        private const string Label = "[\\-0-9_a-z]+";
        private const string Prefix = "(?:[\\-0-9_a-z]+\\.)*";
        public static string Normalize(string value) {
            string result = value.ToLowerInvariant();
            if (result.Length == 0 || result.Length > 253 || !Regex.IsMatch(result, @"^[a-z0-9_\-]+(?:\.[a-z0-9_\-]+)*$"))
                throw new ArgumentException("Unsupported domain syntax: " + value);
            foreach (string label in result.Split('.')) if (label.Length > 63) throw new ArgumentException("Domain label too long.");
            return result;
        }
        public static bool IsGeneratedPositiveRegex(string value) {
            if (String.IsNullOrEmpty(value) || value.Length > 1000000 || !value.StartsWith("(?i)^", StringComparison.Ordinal) || value[value.Length-1] != '$') return false;
            int depth = 0; bool inClass = false;
            for (int index = 0; index < value.Length; index++) {
                char c = value[index];
                if (c == '\\') {
                    if (++index >= value.Length || (value[index] != '.' && value[index] != '-')) return false;
                    continue;
                }
                if (inClass) {
                    if (c == '^') return false;
                    if (c == ']') { inClass = false; continue; }
                    if (!(c == '-' || c == '_' || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))) return false;
                    continue;
                }
                if (c == '[') { inClass = true; continue; }
                if (c == ']') return false;
                if (c == '(') {
                    if (index == 0) { if (!value.StartsWith("(?i)", StringComparison.Ordinal)) return false; index += 3; continue; }
                    if (index + 2 >= value.Length || value[index+1] != '?' || value[index+2] != ':') return false;
                    depth++; index += 2; continue;
                }
                if (c == ')') { if (--depth < 0) return false; continue; }
                if (c == '?' || c == '^') { if (c == '^' && index == 4) continue; return false; }
                if (c == '$') { if (index == value.Length-1) continue; return false; }
                if (c == '|') { if (depth == 0) return false; continue; }
                if (c == '.' || c == '+' || c == '*' || c == '-' || c == '_' ||
                    (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) continue;
                return false;
            }
            if (inClass || depth != 0) return false;
            try { new Regex(value, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant); return true; }
            catch (ArgumentException) { return false; }
        }
        private DomainNode Find(string domain, bool create, out bool covered) {
            string[] labels = Normalize(domain).Split('.');
            DomainNode node = root; covered = false;
            for (int i = labels.Length - 1; i >= 0; i--) {
                if (node.Suffix) { covered = true; return node; }
                DomainNode next;
                if (!node.Children.TryGetValue(labels[i], out next)) {
                    if (!create) return null;
                    next = new DomainNode(); node.Children.Add(labels[i], next);
                }
                node = next;
            }
            if (node.Suffix) covered = true;
            return node;
        }
        public void Block(string value, bool suffix) {
            bool covered; DomainNode node = Find(value, true, out covered);
            if (covered) return;
            if (suffix) { node.Suffix = true; node.Children.Clear(); }
            else node.Exact = true;
        }
        public bool ExactAllowed(string value) {
            bool covered; DomainNode node = Find(value, false, out covered);
            return !covered && (node == null || !node.Exact);
        }
        private static string Join(List<string> alternatives) {
            if (alternatives.Count == 0) return null;
            if (alternatives.Count == 1) return alternatives[0];
            return "(?:" + String.Join("|", alternatives.ToArray()) + ")";
        }
        // Complement a finite set of labels using only positive character
        // alternatives; no lookaround, invert or external exclusion matcher.
        private static string OtherLabel(LabelNode node, bool allowEmpty) {
            if (node.Children.Count == 0) return "[\\-0-9_a-z]" + (allowEmpty && !node.Terminal ? "*" : "+");
            List<string> alternatives = new List<string>();
            if (allowEmpty && !node.Terminal) alternatives.Add("");
            string allowed = "";
            foreach (char c in Alphabet) if (!node.Children.ContainsKey(c)) allowed += c == '-' ? "\\-" : c.ToString();
            if (allowed.Length > 0) alternatives.Add("[" + allowed + "][\\-0-9_a-z]*");
            foreach (KeyValuePair<char, LabelNode> child in node.Children)
                alternatives.Add(Regex.Escape(child.Key.ToString()) + OtherLabel(child.Value, true));
            return Join(alternatives);
        }
        private static string CompilePrefix(DomainNode node) {
            if (node.Suffix) return null;
            List<string> alternatives = new List<string>();
            if (!node.Exact) alternatives.Add("");
            if (node.Children.Count == 0) {
                if (node.Exact) return Label + "\\." + Prefix;
                return Prefix;
            }
            LabelNode labelRoot = new LabelNode();
            foreach (string label in node.Children.Keys) {
                LabelNode cursor = labelRoot;
                foreach (char c in label) {
                    LabelNode next;
                    if (!cursor.Children.TryGetValue(c, out next)) { next = new LabelNode(); cursor.Children.Add(c, next); }
                    cursor = next;
                }
                cursor.Terminal = true;
            }
            alternatives.Add(Prefix + OtherLabel(labelRoot, false) + "\\.");
            foreach (KeyValuePair<string, DomainNode> child in node.Children) {
                string remaining = CompilePrefix(child.Value);
                if (remaining != null) alternatives.Add(remaining + Regex.Escape(child.Key) + "\\.");
            }
            string expression = Join(alternatives);
            if (expression.Length > 1000000) throw new InvalidOperationException("Positive domain automaton exceeds budget; refusing lossy output.");
            return expression;
        }
        // null means fully covered; empty means the original suffix is valid;
        // otherwise return the compiled positive residual domain language.
        public string SuffixPattern(string value) {
            bool covered; DomainNode node = Find(value, false, out covered);
            if (covered) return null;
            if (node == null || (!node.Exact && node.Children.Count == 0)) return "";
            return "(?i)^" + CompilePrefix(node) + Regex.Escape(Normalize(value)) + "$";
        }
    }
    public static class PositiveDomainCompactor {
        private sealed class SuffixComparer : IComparer<string> {
            public int Compare(string left, string right) {
                if (Object.ReferenceEquals(left, right)) return 0;
                if (left == null) return -1;
                if (right == null) return 1;
                int leftDepth = 1, rightDepth = 1;
                for (int index = 0; index < left.Length; index++) if (left[index] == '.') leftDepth++;
                for (int index = 0; index < right.Length; index++) if (right[index] == '.') rightDepth++;
                int depth = leftDepth.CompareTo(rightDepth);
                return depth != 0 ? depth : StringComparer.Ordinal.Compare(left, right);
            }
        }

        // Compact only finite native domain/domain_suffix predicates. Positive
        // complement regexes stay outside this pass and retain their input order.
        public static string[][] Compact(string[] exactValues, string[] suffixValues) {
            List<string> suffixes = new List<string>();
            if (suffixValues != null) foreach (string raw in suffixValues) suffixes.Add(DomainCompiler.Normalize(raw));
            suffixes.Sort(new SuffixComparer());
            HashSet<string> keptSuffixes = new HashSet<string>(StringComparer.Ordinal);
            foreach (string suffix in suffixes) {
                if (keptSuffixes.Contains(suffix)) continue;
                bool covered = false;
                int dot = suffix.IndexOf('.');
                while (dot >= 0) {
                    if (keptSuffixes.Contains(suffix.Substring(dot + 1))) { covered = true; break; }
                    dot = suffix.IndexOf('.', dot + 1);
                }
                if (!covered) keptSuffixes.Add(suffix);
            }

            List<string> exact = new List<string>();
            if (exactValues != null) foreach (string raw in exactValues) exact.Add(DomainCompiler.Normalize(raw));
            exact.Sort(StringComparer.Ordinal);
            List<string> keptExact = new List<string>();
            HashSet<string> seenExact = new HashSet<string>(StringComparer.Ordinal);
            foreach (string domain in exact) {
                if (!seenExact.Add(domain)) continue;
                bool covered = keptSuffixes.Contains(domain);
                int start = 0;
                while (!covered && start < domain.Length) {
                    int dot = domain.IndexOf('.', start);
                    string candidate = dot < 0 ? domain : domain.Substring(dot + 1);
                    if (keptSuffixes.Contains(candidate)) { covered = true; break; }
                    if (dot < 0) break;
                    start = dot + 1;
                }
                if (!covered) keptExact.Add(domain);
            }
            List<string> sortedSuffixes = new List<string>(keptSuffixes);
            sortedSuffixes.Sort(StringComparer.Ordinal);
            return new string[][] { keptExact.ToArray(), sortedSuffixes.ToArray() };
        }
    }
    public sealed class Interval {
        public BigInteger Start, End;
        public int Bits;
        public Interval(BigInteger start, BigInteger end, int bits) { Start=start; End=end; Bits=bits; }
    }
    public static class Ranges {
        public static bool Contains(Interval[] intervals, BigInteger value, int bits) {
            foreach (Interval item in intervals) if (item.Bits == bits && item.Start <= value && value <= item.End) return true;
            return false;
        }
        public static Interval IP(string value) {
            string[] parts = value.Split('/'); IPAddress address;
            if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out address) || parts[0].IndexOf('%') >= 0)
                throw new ArgumentException("Invalid CIDR: " + value);
            byte[] bytes = address.GetAddressBytes(); int bits = bytes.Length * 8;
            if (bits == 32 && !Regex.IsMatch(parts[0], @"^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$")) throw new ArgumentException("Ambiguous IPv4 notation.");
            int prefix = bits;
            if (parts.Length == 2 && (!Regex.IsMatch(parts[1], @"^\d+$") || !Int32.TryParse(parts[1], out prefix) || prefix < 0 || prefix > bits))
                throw new ArgumentException("Invalid CIDR prefix.");
            BigInteger number = BigInteger.Zero;
            foreach (byte b in bytes) number = (number << 8) + b;
            int host = bits - prefix;
            BigInteger start = (number >> host) << host;
            return new Interval(start, start + (BigInteger.One << host) - 1, bits);
        }
        public static Interval Port(int start, int end) {
            if (start < 0 || end > 65535 || start > end) throw new ArgumentException("Invalid port interval.");
            return new Interval(start, end, 16);
        }
        public static Interval[] Merge(Interval[] input) {
            List<Interval> values = new List<Interval>(input);
            values.Sort(delegate(Interval a, Interval b) { int c = a.Bits.CompareTo(b.Bits); return c != 0 ? c : a.Start.CompareTo(b.Start); });
            List<Interval> merged = new List<Interval>();
            foreach (Interval item in values) {
                if (merged.Count == 0 || merged[merged.Count-1].Bits != item.Bits || merged[merged.Count-1].End + 1 < item.Start)
                    merged.Add(new Interval(item.Start,item.End,item.Bits));
                else if (merged[merged.Count-1].End < item.End) merged[merged.Count-1].End = item.End;
            }
            return merged.ToArray();
        }
        public static Interval[] Subtract(Interval[] candidates, Interval[] blockers) {
            Interval[] coverage = Merge(blockers); List<Interval> result = new List<Interval>();
            foreach (Interval item in Merge(candidates)) {
                BigInteger cursor = item.Start;
                int low=0, high=coverage.Length;
                while (low < high) { int mid=(low+high)/2; if (coverage[mid].Bits < item.Bits || (coverage[mid].Bits == item.Bits && coverage[mid].End < cursor)) low=mid+1; else high=mid; }
                for (int i=low; i<coverage.Length && coverage[i].Bits == item.Bits && coverage[i].Start <= item.End; i++) {
                    Interval blocked=coverage[i];
                    if (blocked.Start > cursor) result.Add(new Interval(cursor,blocked.Start-1,item.Bits));
                    if (blocked.End >= cursor) cursor=blocked.End+1;
                    if (cursor > item.End) break;
                }
                if (cursor <= item.End) result.Add(new Interval(cursor,item.End,item.Bits));
            }
            return result.ToArray();
        }
        public static string[] CIDRs(Interval[] ranges) {
            List<string> result = new List<string>();
            foreach (Interval item in ranges) {
                BigInteger cursor = item.Start;
                while (cursor <= item.End) {
                    int host=0;
                    while (host < item.Bits) {
                        BigInteger size=BigInteger.One << (host+1);
                        if (cursor % size != 0 || cursor + size - 1 > item.End) break;
                        host++;
                    }
                    byte[] bytes=new byte[item.Bits/8]; BigInteger number=cursor;
                    for (int i=bytes.Length-1;i>=0;i--) { bytes[i]=(byte)(number & 255); number >>= 8; }
                    result.Add(new IPAddress(bytes).ToString() + "/" + (item.Bits-host));
                    cursor += BigInteger.One << host;
                }
            }
            return result.ToArray();
        }
    }
}
