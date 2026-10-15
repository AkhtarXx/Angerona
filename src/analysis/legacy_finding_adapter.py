"""DEPRECATED — use src.analysis.findings_compat instead.

This module is kept only for backward compatibility with code that imports
``upgrade_result`` from here.  New code must use
``from src.analysis.findings_compat import upgrade_result``.
"""

from .findings_compat import upgrade_result, TRUST_TAG

__all__ = ["upgrade_result", "TRUST_TAG"]
