using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace Bakobo.Fiki
{
    // The RFC 8941 (and RFC 9651) structured-field subset fiki reads, hand-rolled as every port's is
    // (this.i @2q9gv70t, @2tt6fmc0, @5l4p36rl). It reproduces http_sfv 0.9.9, fiki-py's parser,
    // rather than the RFC alone, quirks included: which header parses decides between a Malformed*
    // refusal and a later one, and fiki-py is this port's reference. Where http_sfv departs from
    // the RFC, a comment says so. The oracle is csharp/test/Bakobo.Fiki.Tests/oracle/.

    internal enum SfType { Integer, Decimal, String, Token, ByteSequence, Boolean, Date, DisplayString }

    /// <summary>A bare item.</summary>
    internal sealed class SfValue
    {
        private const long MaxInteger = 999_999_999_999_999;

        private SfValue(SfType type, long integer = 0, decimal number = 0, string text = "", byte[]? bytes = null, bool boolean = false)
        {
            Type = type;
            Integer = integer;
            Decimal = number;
            Text = text;
            Bytes = bytes ?? new byte[0];
            Boolean = boolean;
        }

        internal SfType Type { get; }

        /// <summary>An Integer's or a Date's value.</summary>
        internal long Integer { get; }

        internal decimal Decimal { get; }

        /// <summary>A String's, Token's or Display String's text.</summary>
        internal string Text { get; }

        internal byte[] Bytes { get; }

        internal bool Boolean { get; }

        internal static readonly SfValue True = new SfValue(SfType.Boolean, boolean: true);

        internal static SfValue OfString(string text) => new SfValue(SfType.String, text: text);

        internal static SfValue OfInteger(long value) => new SfValue(SfType.Integer, integer: value);

        internal static SfValue OfDecimal(decimal value) => new SfValue(SfType.Decimal, number: value);

        internal static SfValue OfToken(string text) => new SfValue(SfType.Token, text: text);

        internal static SfValue OfBytes(byte[] bytes) => new SfValue(SfType.ByteSequence, bytes: bytes);

        internal static SfValue OfBoolean(bool value) => new SfValue(SfType.Boolean, boolean: value);

        internal static SfValue OfDate(long seconds) => new SfValue(SfType.Date, integer: seconds);

        internal static SfValue OfDisplayString(string text) => new SfValue(SfType.DisplayString, text: text);

        /// <summary>True for a Boolean true, which a parameter serializes as its bare key.</summary>
        internal bool IsTrue => Type == SfType.Boolean && Boolean;

        internal string Serialize()
        {
            switch (Type)
            {
                case SfType.Integer:
                    if (Integer > MaxInteger || Integer < -MaxInteger)
                    {
                        throw new ArgumentException($"The integer {Integer} is outside RFC 8941's range of 15 digits.");
                    }
                    return Integer.ToString(CultureInfo.InvariantCulture);
                case SfType.Decimal:
                    return SerializeDecimal(Decimal);
                case SfType.String:
                    return SerializeString(Text);
                case SfType.ByteSequence:
                    return ":" + Convert.ToBase64String(Bytes) + ":";
                case SfType.Boolean:
                    return Boolean ? "?1" : "?0";
                case SfType.Date:
                    return "@" + Integer.ToString(CultureInfo.InvariantCulture);
                case SfType.DisplayString:
                    return SerializeDisplayString(Text);
                default:
                    // A token is only ever one this parser read, so it is already well formed.
                    return Text;
            }
        }

        private static string SerializeString(string text)
        {
            var output = new StringBuilder("\"");
            foreach (var c in text)
            {
                if (c < ' ' || c > '~')
                {
                    throw new ArgumentException("An RFC 8941 string carries only visible ASCII and spaces; this one carries something else.");
                }
                if (c == '"' || c == '\\')
                {
                    output.Append('\\');
                }
                output.Append(c);
            }
            return output.Append('"').ToString();
        }

        // http_sfv's ser_decimal: the integer part, then up to three fractional digits with trailing
        // zeros trimmed, or "0" when none remain. A parsed decimal never needs rounding.
        private static string SerializeDecimal(decimal value)
        {
            var text = Math.Abs(value).ToString("0.000", CultureInfo.InvariantCulture);
            var point = text.IndexOf('.');
            var fraction = text.Substring(point + 1).TrimEnd('0');
            return (value < 0 ? "-" : "") + text.Substring(0, point) + "." + (fraction.Length == 0 ? "0" : fraction);
        }

        // http_sfv's ser_display_string, which escapes "%", '"' and bytes outside 31..127 as
        // lowercase hex WITHOUT zero padding, and leaves 0x1F and 0x7F literal.
        private static string SerializeDisplayString(string text)
        {
            var output = new StringBuilder("%\"");
            foreach (var b in new UTF8Encoding(false).GetBytes(text))
            {
                if (b == '%' || b == '"' || b < 31 || b > 127)
                {
                    output.Append('%').Append(b.ToString("x", CultureInfo.InvariantCulture));
                }
                else
                {
                    output.Append((char)b);
                }
            }
            return output.Append('"').ToString();
        }

        /// <summary>
        /// Python's <c>==</c> between the values http_sfv produces, which <c>identity()</c> relies on:
        /// bool, int and Decimal compare as numbers (True == 1); str, Token and DisplayString compare
        /// as text; bytes as bytes; a datetime only with a datetime.
        /// </summary>
        internal bool PyEquals(SfValue other)
        {
            var family = Family(Type);
            if (family != Family(other.Type))
            {
                return false;
            }
            switch (family)
            {
                case 0:
                    return Number() == other.Number();
                case 1:
                    return string.Equals(Text, other.Text, StringComparison.Ordinal);
                case 2:
                    return ByteArrays.Equal(Bytes, other.Bytes);
                default:
                    return Integer == other.Integer;
            }
        }

        private static int Family(SfType type)
        {
            switch (type)
            {
                case SfType.Integer:
                case SfType.Decimal:
                case SfType.Boolean:
                    return 0;
                case SfType.String:
                case SfType.Token:
                case SfType.DisplayString:
                    return 1;
                case SfType.ByteSequence:
                    return 2;
                default:
                    return 3;
            }
        }

        private decimal Number()
        {
            switch (Type)
            {
                case SfType.Integer:
                    return Integer;
                case SfType.Decimal:
                    return Decimal;
                default:
                    return Boolean ? 1 : 0;
            }
        }
    }

    /// <summary>Parameters, in order. A repeated key overwrites in place, as a Python dict does.</summary>
    internal sealed class SfParameters : IEnumerable<KeyValuePair<string, SfValue>>
    {
        private readonly List<KeyValuePair<string, SfValue>> _entries = new List<KeyValuePair<string, SfValue>>();

        // Where each key sits, so a set or a lookup is constant work however many there are.
        private readonly Dictionary<string, int> _index = new Dictionary<string, int>(StringComparer.Ordinal);

        internal int Count => _entries.Count;

        internal void Set(string key, SfValue value)
        {
            var entry = new KeyValuePair<string, SfValue>(key, value);
            if (_index.TryGetValue(key, out var at))
            {
                _entries[at] = entry;
            }
            else
            {
                _index[key] = _entries.Count;
                _entries.Add(entry);
            }
        }

        internal bool Contains(string key) => IndexOf(key) >= 0;

        internal bool TryGet(string key, out SfValue? value)
        {
            var at = IndexOf(key);
            value = at < 0 ? null : _entries[at].Value;
            return at >= 0;
        }

        private int IndexOf(string key) => _index.TryGetValue(key, out var at) ? at : -1;

        internal string Serialize()
        {
            var output = new StringBuilder();
            foreach (var entry in _entries)
            {
                output.Append(';').Append(entry.Key);
                if (!entry.Value.IsTrue)
                {
                    output.Append('=').Append(entry.Value.Serialize());
                }
            }
            return output.ToString();
        }

        public IEnumerator<KeyValuePair<string, SfValue>> GetEnumerator() => _entries.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    /// <summary>A dictionary member: an item or an inner list, each with parameters.</summary>
    internal abstract class SfMember
    {
        internal SfParameters Params { get; } = new SfParameters();

        internal abstract string Serialize();
    }

    internal sealed class SfItem : SfMember
    {
        internal SfItem(SfValue value)
        {
            Value = value;
        }

        internal SfValue Value { get; }

        internal override string Serialize() => Value.Serialize() + Params.Serialize();
    }

    internal sealed class SfInnerList : SfMember
    {
        internal SfInnerList(IEnumerable<SfItem> items)
        {
            Items = new List<SfItem>(items);
        }

        internal IReadOnlyList<SfItem> Items { get; }

        internal override string Serialize()
        {
            var parts = new string[Items.Count];
            for (var i = 0; i < parts.Length; i++)
            {
                parts[i] = Items[i].Serialize();
            }
            return "(" + string.Join(" ", parts) + ")" + Params.Serialize();
        }
    }

    /// <summary>A dictionary, in order. A repeated key overwrites in place, as a Python dict does.</summary>
    internal sealed class SfDictionary : IEnumerable<KeyValuePair<string, SfMember>>
    {
        private readonly List<KeyValuePair<string, SfMember>> _members = new List<KeyValuePair<string, SfMember>>();

        // Where each key sits, so a set or a lookup is constant work however many there are.
        private readonly Dictionary<string, int> _index = new Dictionary<string, int>(StringComparer.Ordinal);

        internal int Count => _members.Count;

        internal void Set(string key, SfMember member)
        {
            var entry = new KeyValuePair<string, SfMember>(key, member);
            if (_index.TryGetValue(key, out var at))
            {
                _members[at] = entry;
            }
            else
            {
                _index[key] = _members.Count;
                _members.Add(entry);
            }
        }

        internal bool TryGet(string key, out SfMember? member)
        {
            var found = _index.TryGetValue(key, out var at);
            member = found ? _members[at].Value : null;
            return found;
        }

        public IEnumerator<KeyValuePair<string, SfMember>> GetEnumerator() => _members.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    /// <summary>The parser. Every failure is a <see cref="FormatException"/>.</summary>
    internal static class Sfv
    {
        private const string Digits = "0123456789";
        private const string Lower = "abcdefghijklmnopqrstuvwxyz";
        private const string Alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        private const string KeyStart = Lower + "*";
        private const string KeyChars = Lower + Digits + "_-*.";
        private const string TokenStart = Alpha + "*";
        private const string TokenChars = Alpha + Digits + ":/!#$%&'*+-.^_`|~";
        private const string Base64Content = Alpha + Digits + "+/=";

        // Python's datetime.fromtimestamp bounds a Date to years 1..9999 in local time, and probes a
        // day earlier to detect a fold, so its lower edge sits a day inside year 1. These are the
        // bounds in UTC; http_sfv's own move with the host's timezone.
        private const long FirstDate = -62_135_510_400;
        private const long LastDate = 253_402_300_799;

        /// <summary>True when <paramref name="text"/> is an RFC 8941 key: a lowercase letter or "*", then lowercase letters, digits, "_", "-", "." and "*".</summary>
        internal static bool IsKey(string text)
        {
            if (text.Length == 0 || KeyStart.IndexOf(text[0]) < 0)
            {
                return false;
            }
            foreach (var c in text)
            {
                if (KeyChars.IndexOf(c) < 0)
                {
                    return false;
                }
            }
            return true;
        }

        internal static SfDictionary ParseDictionary(string text)
        {
            var reader = new Reader(text);
            reader.SkipSpaces();
            var dictionary = new SfDictionary();
            while (true)
            {
                var key = reader.Key();
                SfMember member;
                if (reader.Peek() == '=')
                {
                    reader.Advance();
                    member = reader.ItemOrInnerList();
                }
                else
                {
                    var item = new SfItem(SfValue.True);
                    reader.Parameters(item.Params);
                    member = item;
                }
                dictionary.Set(key, member);
                reader.SkipHttpOws();
                if (reader.AtEnd)
                {
                    return dictionary;
                }
                if (reader.Peek() != ',')
                {
                    throw new FormatException($"Dictionary member '{key}' has trailing characters.");
                }
                reader.Advance();
                reader.SkipHttpOws();
                if (reader.AtEnd)
                {
                    throw new FormatException("Dictionary has a trailing comma.");
                }
            }
        }

        // Top-level OWS is SP only, as http_sfv strips it; the trailing whitespace a dictionary
        // allows between members is SP or HTAB, which is why "a=1\t" parses and "\ta=1" does not.

        internal static SfItem ParseItem(string text)
        {
            var reader = new Reader(text);
            reader.SkipSpaces();
            var item = reader.Item();
            reader.SkipSpaces();
            if (!reader.AtEnd)
            {
                throw new FormatException("Trailing text after the parsed value.");
            }
            return item;
        }

        private sealed class Reader
        {
            private readonly string _text;
            private int _at;

            internal Reader(string text)
            {
                _text = text;
            }

            internal bool AtEnd => _at >= _text.Length;

            /// <summary>The next character, or NUL at the end, which no grammar rule accepts.</summary>
            internal char Peek() => AtEnd ? '\0' : _text[_at];

            internal void Advance() => _at++;

            private char Next()
            {
                if (AtEnd)
                {
                    throw new FormatException("The value ended early.");
                }
                return _text[_at++];
            }

            internal void SkipSpaces()
            {
                while (Peek() == ' ')
                {
                    _at++;
                }
            }

            internal void SkipHttpOws()
            {
                while (Peek() == ' ' || Peek() == '\t')
                {
                    _at++;
                }
            }

            private static bool In(char c, string set) => c != '\0' && set.IndexOf(c) >= 0;

            internal string Key()
            {
                if (!In(Peek(), KeyStart))
                {
                    throw new FormatException("A key does not begin with a lowercase letter or \"*\".");
                }
                var start = _at++;
                while (In(Peek(), KeyChars))
                {
                    _at++;
                }
                return _text.Substring(start, _at - start);
            }

            internal SfMember ItemOrInnerList() => Peek() == '(' ? InnerList() : Item();

            private SfInnerList InnerList()
            {
                _at++; // "("
                var items = new List<SfItem>();
                while (true)
                {
                    SkipSpaces();
                    if (Peek() == ')')
                    {
                        _at++;
                        var list = new SfInnerList(items);
                        Parameters(list.Params);
                        return list;
                    }
                    items.Add(Item());
                    if (Peek() != ' ' && Peek() != ')')
                    {
                        throw new FormatException("An inner list's items are separated by spaces and closed by \")\".");
                    }
                }
            }

            internal SfItem Item()
            {
                var item = new SfItem(BareItem());
                Parameters(item.Params);
                return item;
            }

            internal void Parameters(SfParameters parameters)
            {
                while (Peek() == ';')
                {
                    _at++;
                    SkipSpaces();
                    var key = Key();
                    var value = SfValue.True;
                    if (Peek() == '=')
                    {
                        _at++;
                        value = BareItem();
                    }
                    parameters.Set(key, value);
                }
            }

            private SfValue BareItem()
            {
                var c = Peek();
                if (c == '"')
                {
                    return SfValue.OfString(String());
                }
                if (c == ':')
                {
                    return SfValue.OfBytes(ByteSequence());
                }
                if (c == '?')
                {
                    return Boolean();
                }
                if (c == '@')
                {
                    return Date();
                }
                if (c == '%')
                {
                    return DisplayString();
                }
                if (In(c, TokenStart))
                {
                    return Token();
                }
                if (In(c, Digits + "-"))
                {
                    return Number();
                }
                throw new FormatException("An item begins with a character no item type starts with.");
            }

            private string String()
            {
                _at++; // the opening quote
                var output = new StringBuilder();
                while (true)
                {
                    var c = Next();
                    if (c == '\\')
                    {
                        var escaped = Next();
                        if (escaped != '"' && escaped != '\\')
                        {
                            throw new FormatException("A backslash in a string escapes only a quote or a backslash.");
                        }
                        output.Append(escaped);
                    }
                    else if (c == '"')
                    {
                        return output.ToString();
                    }
                    else if (c < ' ' || c > '~')
                    {
                        throw new FormatException("A string carries a character outside visible ASCII.");
                    }
                    else
                    {
                        output.Append(c);
                    }
                }
            }

            private SfValue Token()
            {
                var start = _at++;
                while (In(Peek(), TokenChars))
                {
                    _at++;
                }
                return SfValue.OfToken(_text.Substring(start, _at - start));
            }

            private byte[] ByteSequence()
            {
                _at++; // the opening colon
                var end = _text.IndexOf(':', _at);
                if (end < 0)
                {
                    throw new FormatException("A byte sequence has no closing colon.");
                }
                var content = _text.Substring(_at, end - _at);
                _at = end + 1;
                foreach (var c in content)
                {
                    if (!In(c, Base64Content))
                    {
                        throw new FormatException("A byte sequence carries a character outside base64.");
                    }
                }
                return PyBase64.Decode(content);
            }

            private SfValue Boolean()
            {
                _at++; // "?"
                var c = Next();
                if (c == '1' || c == '0')
                {
                    return SfValue.OfBoolean(c == '1');
                }
                throw new FormatException("A boolean is ?1 or ?0.");
            }

            private SfValue Date()
            {
                _at++; // "@"
                var number = Number();
                if (number.Type != SfType.Integer || number.Integer < FirstDate || number.Integer > LastDate)
                {
                    throw new FormatException("A date is an integer number of seconds within years 1 to 9999.");
                }
                return SfValue.OfDate(number.Integer);
            }

            // http_sfv's parse_number, including its one quirk: it checks for a trailing MINUS where
            // it means a trailing PERIOD, so "1." parses as the decimal 1.0.
            private SfValue Number()
            {
                var negative = Peek() == '-';
                if (negative)
                {
                    _at++;
                }
                if (!In(Peek(), Digits))
                {
                    throw new FormatException("A number begins with a digit.");
                }
                var start = _at;
                var point = -1;
                while (true)
                {
                    var c = Peek();
                    if (In(c, Digits))
                    {
                        _at++;
                    }
                    else if (c == '.' && point < 0)
                    {
                        if (_at - start > 12)
                        {
                            throw new FormatException("A decimal's integer part is at most 12 digits.");
                        }
                        point = _at++;
                    }
                    else
                    {
                        break;
                    }
                }
                var digits = _text.Substring(start, _at - start);
                if (point < 0)
                {
                    // http_sfv counts one digit fewer when the number ends the header, so there it
                    // admits a sixteenth digit, and only the range check that follows refuses it:
                    // "0000000000000001" at the end of a header parses as 1.
                    if (digits.Length > (AtEnd ? 16 : 15))
                    {
                        throw new FormatException("An integer is at most 15 digits.");
                    }
                    var value = long.Parse(digits, NumberStyles.None, CultureInfo.InvariantCulture);
                    if (value > 999_999_999_999_999)
                    {
                        throw new FormatException("An integer is at most 15 digits.");
                    }
                    return SfValue.OfInteger(negative ? -value : value);
                }
                if (_at - point - 1 > 3)
                {
                    throw new FormatException("A decimal's fractional part is at most 3 digits.");
                }
                var number = decimal.Parse(digits.TrimEnd('.'), NumberStyles.AllowDecimalPoint, CultureInfo.InvariantCulture);
                return SfValue.OfDecimal(negative ? -number : number);
            }

            private SfValue DisplayString()
            {
                _at++; // "%"
                if (Next() != '"')
                {
                    throw new FormatException("A display string begins with %\".");
                }
                var output = new List<byte>();
                while (true)
                {
                    var c = Next();
                    if (c == '%')
                    {
                        if (_text.Length - _at < 2)
                        {
                            throw new FormatException("A display string ends inside a percent escape.");
                        }
                        output.Add(PercentOctet(_text.Substring(_at, 2)));
                        _at += 2;
                    }
                    else if (c == '"')
                    {
                        try
                        {
                            return SfValue.OfDisplayString(new UTF8Encoding(false, true).GetString(output.ToArray()));
                        }
                        catch (ArgumentException ex)
                        {
                            throw new FormatException("A display string is not valid UTF-8.", ex);
                        }
                    }
                    else if (c > 31 && c < 127)
                    {
                        output.Add((byte)c);
                    }
                    else
                    {
                        throw new FormatException("A display string carries a character outside visible ASCII.");
                    }
                }
            }

            // http_sfv reads a percent escape with Python's int(chunk, 16) after refusing uppercase,
            // so it also takes one hex digit with whitespace beside it, or behind a sign: "% a",
            // "a\v", "+a", and "-0", whose value is zero.
            private static byte PercentOctet(string chunk)
            {
                const string PySpace = " \t\n\v\f\r";
                var body = chunk.Trim(PySpace.ToCharArray());
                var negative = false;
                if (body.Length > 0 && (body[0] == '+' || body[0] == '-'))
                {
                    negative = body[0] == '-';
                    body = body.Substring(1);
                }
                const string Hex = "0123456789abcdef";
                var value = 0;
                foreach (var c in body)
                {
                    var digit = Hex.IndexOf(c);
                    if (digit < 0)
                    {
                        throw new FormatException("A percent escape in a display string is not lowercase hex.");
                    }
                    value = value * 16 + digit;
                }
                if (body.Length == 0 || (negative && value != 0))
                {
                    throw new FormatException("A percent escape in a display string is not lowercase hex.");
                }
                return (byte)value;
            }
        }
    }

    /// <summary>
    /// CPython 3.14's non-strict <c>binascii.a2b_base64</c>, which http_sfv decodes byte sequences
    /// with, over input already limited to the base64 alphabet and "=". It ignores "=" wherever it
    /// cannot be padding, and refuses only a dangling character or a short final quantum.
    /// </summary>
    internal static class PyBase64
    {
        private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

        internal static byte[] Decode(string content)
        {
            var output = new List<byte>();
            var quad = 0;
            var left = 0;
            var pads = 0;
            foreach (var c in content)
            {
                if (c == '=')
                {
                    pads++;
                    continue;
                }
                var value = Alphabet.IndexOf(c);
                pads = 0;
                switch (quad)
                {
                    case 0:
                        left = value;
                        break;
                    case 1:
                        output.Add((byte)((left << 2) | (value >> 4)));
                        left = value & 0x0f;
                        break;
                    case 2:
                        output.Add((byte)((left << 4) | (value >> 2)));
                        left = value & 0x03;
                        break;
                    default:
                        output.Add((byte)((left << 6) | value));
                        break;
                }
                quad = (quad + 1) % 4;
            }
            if (quad == 1 || (quad != 0 && quad + pads < 4))
            {
                throw new FormatException("A byte sequence is not padded base64.");
            }
            return output.ToArray();
        }
    }

    internal static class ByteArrays
    {
        internal static bool Equal(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }
            var difference = 0;
            for (var i = 0; i < a.Length; i++)
            {
                difference |= a[i] ^ b[i];
            }
            return difference == 0;
        }
    }
}
