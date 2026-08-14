"""Canonicalization used only for security analysis of untrusted metadata."""

from __future__ import annotations

import unicodedata


def normalize_for_analysis(value: str) -> str:
    """Make common invisible-character and spacing evasions visible to rules.

    The original descriptor is retained for reports and baselines. This helper
    only produces an analysis view: compatibility-normalized Unicode, format
    controls removed, and whitespace collapsed. It intentionally does not try
    to map Unicode homoglyphs across writing systems, which would risk
    rewriting legitimate metadata and producing misleading evidence.
    """
    compatibility_normalized = unicodedata.normalize("NFKC", value)
    without_format_controls = "".join(
        character
        for character in compatibility_normalized
        if unicodedata.category(character) != "Cf"
    )
    return " ".join(without_format_controls.split())
