#!/usr/bin/env python3
"""Write url-oracle.json: what urllib.parse.urlsplit, which fiki-py derives @authority, @path and
@query with, makes of a corpus of URLs.

The C# port reproduces urlsplit rather than using System.Uri, which normalizes paths and
percent-encoding and so would build a different signature base from the same URL.

Run from py/ so the interpreter is fiki-py's:  uv run python ../csharp/test/Bakobo.Fiki.Tests/oracle/url_oracle.py
"""

import json
from pathlib import Path
from urllib.parse import urlsplit

URLS = [
    "https://example.com/foo?param=Value&Pet=dog", "https://EXAMPLE.com:443/f", "https://example.com:8443/f",
    "http://example.com:80/", "http://example.com:443/", "https://example.com", "https://example.com?x",
    "https://example.com#frag", "https://example.com/p?q#f", "https://example.com/p#f?q", "/things?limit=1",
    "/x", "", "?", "#", "//host/path", "//host", "///path", "https:", "https:/path", "https:path",
    "HTTPS://Example.COM/A?B", "Https://h/", "1http://h/", "ht@tp://h/", "h+t.t-p://h/", "x:", ":",
    "mailto:a@b", "https://user:pass@Host.example:8080/p", "https://user@host/", "https://@host/",
    "https://host:/p", "https://host:0/", "https://host:65535/", "https://host:65536/", "https://host:-1/",
    "https://host:+1/", "https://host:abc/", "https://host:08443/", "https://host: 80/", "https://host:٣/",
    "https://[::1]/", "https://[::1]:8080/", "https://[::1]x/", "https://[::1]:x/", "https://x[::1]/",
    "https://[::1/", "https://::1]/", "https://[127.0.0.1]/", "https://[v1.fe]/", "https://[v1.]/",
    "https://[vz.x]/", "https://[V1.x]/", "https://[fe80::1%25eth0]/", "https://[fe80::1%eTh0]:1/",
    "https://[fe80::1%]/", "https://[fe80::1%a%b]/", "https://[1:2:3:4:5:6:7:8]/", "https://[1:2:3:4:5:6:7:8:9]/",
    "https://[1:2:3:4:5:6:7]/", "https://[::]/", "https://[1::2::3]/", "https://[:1:2:3:4:5:6:7]/",
    "https://[1:2:3:4:5:6:7:]/", "https://[::ffff:1.2.3.4]/", "https://[::ffff:1.2.3.04]/",
    "https://[::ffff:1.2.3.256]/", "https://[::1.2.3]/", "https://[12345::]/", "https://[g::]/",
    "https://[1:2:3:4:5:6:7::]/", "https://[::1:2:3:4:5:6:7]/", "https://[::1:2:3:4:5:6:7:8]/",
    "https://[1/2::]/", "https://[]/", "https://[::1]@x/", "https://a@[::1]:5/", "https://[a@b]/",
    "https://[0000:0000:0000:0000:0000:0000:0000:0001]/", "https://[0000:0000:0000:0000:0000:0000:0000:00001]/",
    "https://[::1]]/", "https://[[::1]/", "https://[::1][::2]/",
    "  https://h/p", "\x00https://h/p", "https://h/p  ", "ht\ttp://h/p\r\n", "https://h\n/p", "https://h/p?a\tb",
    "https://h/%2Fa?%2Db", "https://h/p;x?y", "https://hé.example/", "https://h\u2100.example/",
    "https://\u2100/", "https://h\uff03x/", "https://ÉXAMPLE.com/", "https://İ.example/",
]


def entry(url):
    try:
        parts = urlsplit(url)
    except ValueError:
        return {"input": url, "error": True}
    out = {"input": url, "error": False, "scheme": parts.scheme, "netloc": parts.netloc,
           "path": parts.path, "query": parts.query, "fragment": parts.fragment,
           "hostname": parts.hostname}
    try:
        out["port"] = parts.port
    except ValueError:
        out["port"] = "error"
    return out


def main():
    out = {"about": "urlsplit's verdict on each URL, with .hostname and .port ('error' when it raises).",
           "cases": [entry(url) for url in URLS]}
    target = Path(__file__).with_name("url-oracle.json")
    target.write_text(json.dumps(out, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
