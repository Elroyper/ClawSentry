"""Tests for text_utils — Unicode normalization + invisible char utilities."""

import pytest
from clawsentry.gateway.text_utils import (
    INVISIBLE_CODEPOINTS,
    normalize_text,
    count_invisible_chars,
)


class TestInvisibleCodepoints:
    def test_contains_zero_width_space(self):
        assert 0x200B in INVISIBLE_CODEPOINTS

    def test_contains_bidi_override(self):
        assert 0x202E in INVISIBLE_CODEPOINTS

    def test_excludes_emoji_vs16(self):
        # U+FE0F is VS-16, used in emoji — must NOT be in set
        assert 0xFE0F not in INVISIBLE_CODEPOINTS

    def test_contains_vs1_through_vs15(self):
        for cp in range(0xFE00, 0xFE0F):
            assert cp in INVISIBLE_CODEPOINTS

    def test_contains_tag_chars(self):
        assert 0xE0020 in INVISIBLE_CODEPOINTS
        assert 0xE007F in INVISIBLE_CODEPOINTS

    def test_count_is_exact(self):
        """Exact count ensures no accidental additions/removals."""
        assert len(INVISIBLE_CODEPOINTS) == 393


class TestNormalizeText:
    def test_strips_zero_width_space(self):
        assert normalize_text("he\u200bllo") == "hello"

    def test_strips_bidi_override(self):
        assert normalize_text("test\u202Etext") == "testtext"

    def test_nfkc_fullwidth_to_ascii(self):
        # Fullwidth "Ignore" → "Ignore"
        assert normalize_text("\uff29\uff47\uff4e\uff4f\uff52\uff45") == "Ignore"

    def test_preserves_normal_text(self):
        assert normalize_text("Hello World 123") == "Hello World 123"

    def test_preserves_cjk(self):
        assert normalize_text("你好世界") == "你好世界"

    def test_preserves_emoji_vs16(self):
        # ❤️ = U+2764 + U+FE0F — FE0F should NOT be stripped
        assert normalize_text("❤\uFE0F") == "❤\uFE0F"


class TestCountInvisibleChars:
    def test_zero_for_clean_text(self):
        assert count_invisible_chars("Hello World") == 0

    def test_counts_zero_width_space(self):
        assert count_invisible_chars("he\u200bllo") == 1

    def test_counts_multiple(self):
        assert count_invisible_chars("\u200b\u200c\u200d") == 3

    def test_does_not_count_emoji_vs16(self):
        assert count_invisible_chars("❤\uFE0F") == 0

    def test_counts_tag_chars(self):
        assert count_invisible_chars("\U000E0020\U000E0067") == 2


class TestEdgeCases:
    def test_normalize_empty_string(self):
        assert normalize_text("") == ""

    def test_count_empty_string(self):
        assert count_invisible_chars("") == 0
