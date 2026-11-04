"""Keep share-link secrets out of access logs.

uvicorn's access log records the full request line, which for the public share
endpoint contains the bearer-like token (``/share/<token>``) and, if the viewer
used it, the link password (``?password=...``). Logs are widely readable and
long-lived, so both are redacted before the line is written.
"""
import logging
import re

_SHARE_PATH = re.compile(r"(/share/)[^/?\s\"]+")
_PASSWORD_QS = re.compile(r"([?&]password=)[^&\s\"]*", re.IGNORECASE)


def redact(text: str) -> str:
    return _PASSWORD_QS.sub(r"\1[redacted]", _SHARE_PATH.sub(r"\1[redacted]", text))


class RedactShareSecrets(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        return True
