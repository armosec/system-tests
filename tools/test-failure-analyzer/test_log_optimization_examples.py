#!/usr/bin/env python3
"""
Unit tests for log_optimization_examples.py
"""

import unittest

from log_optimization_examples import optimize_logs_for_llm


class TestLogOptimizationExamples(unittest.TestCase):
    def test_preserve_patterns_pins_lines_even_when_over_max_snippets(self):
        logs = [
            "noise 1",
            "2026-01-08T15:21:10Z INFO something",
            '2026-01-08T15:21:12Z ERROR Request failed "Request body":"{...}" HTTP status":400',
            "noise 2",
            '2026-01-08T15:21:12Z ERROR Request failed "Response body":"Feature with accountID already exists"',
            "noise 3",
        ]

        out = optimize_logs_for_llm(
            logs,
            max_snippets=2,
            max_chars=10_000,
            preserve_patterns=[r"\bRequest body\b", r"\bResponse body\b"],
        )

        self.assertEqual(len(out), 2)
        self.assertIn("Request body", out[0] + out[1])
        self.assertIn("Response body", out[0] + out[1])

    def test_preserve_patterns_keeps_duplicate_high_signal_lines(self):
        logs = [
            'ERROR Request failed "Request body":"{a}" HTTP status":400',
            'ERROR Request failed "Request body":"{a}" HTTP status":400',
            "some other error",
        ]

        out = optimize_logs_for_llm(
            logs,
            max_snippets=10,
            max_chars=10_000,
            preserve_patterns=[r"\bRequest failed\b"],
        )

        # Both should be preserved (we prefer keeping signal over deduping it away).
        self.assertGreaterEqual(sum(1 for x in out if "Request failed" in x), 2)

    def test_summarization_keeps_pinned_plus_summary(self):
        pinned = 'ERROR Request failed "Request body":"{...}" HTTP status":400'
        long_noise = ["INFO " + ("x" * 200) for _ in range(20)]
        out = optimize_logs_for_llm(
            [pinned] + long_noise,
            max_snippets=50,
            max_chars=300,
            preserve_patterns=[r"\bRequest failed\b", r"\bRequest body\b"],
        )

        # First element should be pinned, and we should still return something summarized.
        self.assertGreaterEqual(len(out), 2)
        self.assertIn("Request failed", out[0])


if __name__ == "__main__":
    unittest.main()


