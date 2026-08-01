# Author : Krishnendu De
# Co-Author: Claude Fable 5.0
"""The one LOQL error type — raised at the parse/compile boundary (the security
gate), so a malformed or unsupported query is a clean 400, never a 500 or an
injection. Carries an optional character position for editor feedback."""
from __future__ import annotations

from typing import Optional


class LoqlError(Exception):
    def __init__(self, message: str, pos: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.pos = pos
