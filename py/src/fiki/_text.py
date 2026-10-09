"""How an error message quotes a value it was handed (``this.i`` @524c8qgv).

Every refusal's message holds no control character and is at most 1024 characters, which every
port's vector driver checks; an untrusted value is quoted escaped and cut at 64 characters.
"""

from __future__ import annotations

# Longest stretch of an untrusted value an error message quotes.
_SHOWN = 64


def shown(text: str) -> str:
    """An untrusted value as an error message may quote it: escaped, and cut at 64 characters.

    Total over any value, so that building a message never raises before the refusal it carries.
    """
    if not isinstance(text, str):
        return repr(text)[:_SHOWN]
    if len(text) <= _SHOWN:
        return repr(text)
    return repr(text[:_SHOWN]) + f" (cut from {len(text)} characters)"


def brief(text: str) -> str:
    """A short printable value as it is, anything else as shown() quotes it.

    For a name a message reads naturally with bare -- a component, a label, a keyid -- so that
    an honest one reads as before, and a long or unprintable one cannot inflate the message.
    """
    text = str(text)
    if len(text) <= _SHOWN and all(" " <= c <= "~" for c in text):
        return text
    return shown(text)
