import pytest
from clawsentry.gateway.safe_regex import compile_safe_regex, has_nested_repetition


class TestNestedRepetitionDetection:
    def test_safe_simple_pattern(self):
        assert not has_nested_repetition(r"hello\s+world")

    def test_safe_character_class(self):
        assert not has_nested_repetition(r"[a-z]+\d{2,4}")

    def test_safe_alternation_no_outer_quantifier(self):
        assert not has_nested_repetition(r"(cat|dog)")

    def test_safe_fixed_repetition(self):
        assert not has_nested_repetition(r"(ab){3}")

    def test_safe_non_greedy(self):
        assert not has_nested_repetition(r".*?hello")

    def test_safe_typical_attack_pattern(self):
        # Typical pattern from attack_patterns.yaml
        assert not has_nested_repetition(r"curl\s+.*\|\s*bash")

    def test_unsafe_nested_plus(self):
        assert has_nested_repetition(r"(a+)+")

    def test_unsafe_nested_star(self):
        assert has_nested_repetition(r"(a*)*")

    def test_unsafe_nested_star_plus(self):
        assert has_nested_repetition(r"(a*)+")

    def test_unsafe_alternation_with_quantifier(self):
        # (a|aa)+ — alternation inside quantified group
        assert has_nested_repetition(r"(a|aa)+")

    def test_unsafe_alternation_star(self):
        assert has_nested_repetition(r"(a|b)+")

    def test_safe_escaped_parens(self):
        # \( and \) are literal, not grouping
        assert not has_nested_repetition(r"\(a+\)+")


class TestCompileSafeRegex:
    def test_compiles_safe_pattern(self):
        result = compile_safe_regex(r"curl\s+.*\|\s*bash")
        assert result is not None

    def test_rejects_redos_pattern(self):
        result = compile_safe_regex(r"(a+)+b")
        assert result is None

    def test_rejects_invalid_regex(self):
        result = compile_safe_regex(r"[invalid")
        assert result is None

    def test_rejects_empty(self):
        result = compile_safe_regex("")
        assert result is None

    def test_returns_compiled_pattern(self):
        result = compile_safe_regex(r"hello\s+world")
        assert result is not None
        assert result.search("hello   world")

    def test_logs_warning_on_rejection(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING):
            compile_safe_regex(r"(a+)+b")
        assert "ReDoS" in caplog.text


class TestCharClassEdgeCases:
    def test_bracket_as_first_char_in_class(self):
        """[]] is a valid char class containing literal ']' — parser must not break."""
        assert has_nested_repetition(r"[]]abc(a+)+")

    def test_negated_bracket_first(self):
        """[^]] is also a valid char class."""
        assert has_nested_repetition(r"[^]]foo(a+)+")

    def test_char_class_with_quantified_content_inside_group(self):
        """([a-z]+)+ is ReDoS-prone and should be detected."""
        assert has_nested_repetition(r"([a-z]+)+")


class TestKnownGaps:
    def test_adjacent_quantified_atoms_documented_gap(self):
        r"""Known gap: \d+\d+ is not detected (only group nesting checked)."""
        result = has_nested_repetition(r"\d+\d+")
        assert not result, "Known gap: adjacent quantified atoms not detected"

    def test_adjacent_quantified_groups_with_alternation_detected(self):
        """(a|b)+(a|b)+ IS detected because each group has alternation + quantifier."""
        assert has_nested_repetition(r"(a|b)+(a|b)+")

    def test_adjacent_plain_groups_documented_gap(self):
        """Known gap: (ab)+(cd)+ — adjacent quantified groups without inner complexity."""
        result = has_nested_repetition(r"(ab)+(cd)+")
        assert not result, "Known gap: adjacent quantified plain groups not detected"
