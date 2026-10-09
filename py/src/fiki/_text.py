"""How an error message quotes a value it was handed (``this.i`` @524c8qgv).

Every refusal's message holds no control character and is at most 1024 characters, which every
port's vector driver checks; an untrusted value is quoted escaped and cut at 64 characters.
"""

from __future__ import annotations

# Longest stretch of an untrusted value an error message quotes.
_SHOWN = 64


def shown(text: str) -> str:
    """An untrusted value as an error message may quote it: escaped, and cut at 64 characters.

    Never raises for a value that arrived in a message, which is always a plain str, nor for a
    plain non-string fiki itself passes, which is quoted by its type name without calling the
    value's own methods. An object a caller builds to be hostile -- a metaclass whose __name__
    raises, a str subclass whose __len__ does -- runs the caller's own code, and no message helper
    can be total against that (#18 hostile fix pass, and a GLM reading of it).
    """
    if not isinstance(text, str):
        # Never the value's own __repr__, which an object can make raise (#18 hostile fix pass).
        return f"<{type(text).__name__}>"[:_SHOWN]
    if len(text) <= _SHOWN:
        return repr(text)
    return repr(text[:_SHOWN]) + f" (cut from {len(text)} characters)"


def brief(text: str) -> str:
    """A short printable value as it is, anything else as shown() quotes it.

    For a name a message reads naturally with bare -- a component, a label, a keyid -- so that
    an honest one reads as before, and a long or unprintable one cannot inflate the message.
    """
    if not isinstance(text, str):
        return shown(text)
    if len(text) <= _SHOWN and all(" " <= c <= "~" for c in text):
        return text
    return shown(text)
