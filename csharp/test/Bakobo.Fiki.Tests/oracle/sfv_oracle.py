#!/usr/bin/env python3
"""Write sfv-oracle.json: what http_sfv, fiki-py's RFC 8941 parser, makes of a corpus of headers.

The C# port hand-rolls its parser (this.i @5l4p36rl, @2q9gv70t), and which header parses decides
between a Malformed* refusal and a later one, so its parser has to agree with py's on every input,
quirks included. Byte sequences decode through CPython's non-strict base64, whose treatment of
"=" changed in 3.14; this corpus is generated under 3.14, as fiki-py's lockfile environment is. This corpus is the standing oracle; a wider random differential is run by hand.

Run from py/ so http_sfv resolves:  TZ=UTC uv run python ../csharp/test/Bakobo.Fiki.Tests/oracle/sfv_oracle.py
"""

import json
from pathlib import Path

import http_sfv

DICTIONARIES = [
    # the shapes fiki reads
    'sig=("@method" "@path");created=1;keyid="k"',
    'sig=:AAAA:', 'sig=:AAAA:, other=:BBBB:', 'sig=:AAAA:,other=:BBBB:', 'sig=:AAAA:\t,\tother=:BBBB:',
    'sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:',
    'a=1, a=2', 'a=1, b=2, a=3', 'a;x=1;x=2', 'a=("x";p=1;p=2)',
    # whitespace and empties
    '', ' ', '  a=1  ', '\ta=1', 'a=1\t', 'a=1,', 'a=1, ', ',a=1', 'a=1,,b=2', 'a=1 b=2', 'a=1 , b=2',
    # keys
    'A=1', '*a=1', '1a=1', 'a.b-c_d*e=1', 'a B=1', 'a', 'a;b', 'a;b=?0', 'a; b', 'a;  b=1', 'a;B=1',
    # integers and decimals
    'a=0', 'a=-0', 'a=007', 'a=-', 'a=-a', 'a=999999999999999', 'a=1000000000000000',
    'a=-999999999999999', 'a=9999999999999999', 'a=1.5', 'a=1.', 'a=-1.', 'a=1.50', 'a=1.500',
    'a=1.5000', 'a=123456789012.123', 'a=1234567890123.1', 'a=-0.0', 'a=0.001', 'a=100.0', 'a=1..2',
    'a=1.2.3', 'a=12345678901234567', 'a=0000000000000001', 'a=-0000000000000001',
    'a=0000000000000001;p', 'a=@0000000000000001', 'a=(0000000000000001)', 'a=1;p=0000000000000001',
    # strings
    'a="x"', 'a=""', 'a="\\"q\\""', 'a="\\\\"', 'a="\\x"', 'a="unterminated', 'a="tab\there"',
    'a="café"', 'a="\x7f"', 'a="~"',
    # tokens
    'a=tok', 'a=*tok', 'a=t:o/k!#$%&\'*+-.^_`|~', 'a=Tok9', 'a=t@k',
    # byte sequences, through CPython's non-strict base64
    'a=::', 'a=:QQ==:', 'a=:QQ=:', 'a=:QQ:', 'a=:QUJD:', 'a=:QUJD=QQ==:', 'a=:QQ=x=:', 'a=:Q===:',
    'a=:=QQ==:', 'a=:Q:', 'a=:QUJDRA:', 'a=:QU JD:', 'a=:QUJD', 'a=:-_-_:', 'a=:QQ==QQ==:',
    'a=:QQ=:=:', 'a=:QUI=:', 'a=:QUJ:', 'a=:A===:', 'a=:AA=A:', 'a=:==:', 'a=:=:',
    # booleans
    'a=?1', 'a=?0', 'a=?2', 'a=?', 'a=?10',
    # dates
    # Python's datetime.fromtimestamp bounds them to years 1..9999 in LOCAL time, and probes a day
    # earlier to detect a fold, so the lower edge moves with the timezone; generate under TZ=UTC.
    'a=@0', 'a=@1700000000', 'a=@-1', 'a=@1.5', 'a=@', 'a=@x', 'a=@253402300799', 'a=@253402300800',
    'a=@-62135510400', 'a=@-62135510401', 'a=@999999999999999',
    # display strings, through Python's int(x, 16)
    'a=%"x"', 'a=%""', 'a=%"%c3%a9"', 'a=%"%C3%A9"', 'a=%"%e9"', 'a=%"%25"', 'a=%"%22"', 'a=%"%7f"',
    'a=%"%1f"', 'a=%"% a"', 'a=%"%a "', 'a=%"%+a"', 'a=%"%-a"', 'a=%"%-0"', 'a=%"%_a"', 'a=%"%g0"',
    'a=%"%0"', 'a=%"%', 'a=%"%a', 'a=%"\x7f"', 'a=%x', 'a=%"un', 'a=%"%\ta"', 'a=%"%0x"', 'a=%"%a\x0b"',
    'a=%"\\"',
    # inner lists
    'a=()', 'a=( )', 'a=(  "x"  )', 'a=("x""y")', 'a=("x" "y");p', 'a=("x";q "y")', 'a=("x"', 'a=(',
    'a=("x")x', 'a=(1 2.5 tok ?0 :QQ==: @1 %"d")', 'a=(("x"))', 'a=("x"\t"y")', 'a=("x",)',
    # non-ASCII anywhere
    'café=1', 'a=é', 'a=1;é', '((((', 'not a dictionary (((', 'not a dictionary («',
    'indexed="?0";signify="0BBWiqPdnUjfwk"',
]

ITEMS = [
    '"@path"', '"@path";req', '"@PATH"', '"@path', '"@path";req=?0', '"@path";req;sf', ' "@path" ',
    '"@path" x', '"x";p=1.5', '"x";p=tok', '"x";p=:QQ==:', '"x";p=@5', '"x";p=%"d"', '"x";p="s"',
    '"x";p=-3', '"x"; p', '"x";p;p=2', '',
]


def dump_dictionary(text):
    parsed = http_sfv.Dictionary()
    try:
        parsed.parse(text.encode("utf-8"))
    except Exception:
        return None
    return str(parsed)


def dump_item(text):
    parsed = http_sfv.Item()
    try:
        parsed.parse(text.encode("utf-8"))
    except Exception:
        return None
    return str(parsed)


def main():
    out = {
        "about": "http_sfv's verdict on each input: null when it does not parse, else its reserialization.",
        "http_sfv": http_sfv.__version__ if hasattr(http_sfv, "__version__") else "0.9.9",
        "dictionaries": [{"input": d, "parsed": dump_dictionary(d)} for d in DICTIONARIES],
        "items": [{"input": i, "parsed": dump_item(i)} for i in ITEMS],
    }
    target = Path(__file__).with_name("sfv-oracle.json")
    target.write_text(json.dumps(out, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
