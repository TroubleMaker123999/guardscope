"""Scanner output parsers.

Each parser converts a tool's native report format into a list of normalized
:class:`~guardscope.core.models.Finding` objects. Parsers are intentionally
defensive — they tolerate missing fields and produce sensible defaults.
"""

from .base import Parser, ParseError
from .manager import dispatch, list_parsers

__all__ = ["Parser", "ParseError", "dispatch", "list_parsers"]