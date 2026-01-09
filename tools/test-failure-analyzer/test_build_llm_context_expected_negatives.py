#!/usr/bin/env python3
"""
Unit tests for expected-negative (true negative) handling in build_llm_context.py.
"""

import unittest

from build_llm_context import (
    _extract_expected_negative_markers,
    _find_expected_negative_log_lines,
)


class TestExpectedNegatives(unittest.TestCase):
    def test_extracts_bad_marker_and_placeholder_arn(self):
        test_code = """
bad_arn = "arn:aws:iam::12345678:role/armo-scan-role-cross-with_customer-12345678"
cspm_bad_cloud_account_name = "systest-" + self.test_identifier_rand + "-cspm-bad"
cloud_account_guid_bad = self.create_and_validate_cloud_account_with_cspm_aws(
    cspm_bad_cloud_account_name, bad_arn, stack_region, expect_failure=True
)
"""
        markers = _extract_expected_negative_markers(test_code)
        patterns = [m.get("pattern") for m in markers]

        self.assertTrue(any("expect_failure=True" in p for p in patterns))
        self.assertTrue(any("cspm\\-bad" in p for p in patterns))
        # placeholder account-ID ARN prefix pattern
        self.assertTrue(any("arn:aws:iam::12345678" in p for p in patterns))

    def test_finds_expected_negative_lines_in_logs(self):
        markers = _extract_expected_negative_markers(
            'bad_arn = "arn:aws:iam::12345678:role/armo-scan-role-cross-with_customer-12345678"\n'
            'cspm_bad_cloud_account_name = "systest-" + "-cspm-bad"\n'
            "x = f()  # expect_failure=True\n"
        )
        error_logs = "\n".join(
            [
                '{"level":"info","roleArn":"arn:aws:iam::12345678:role/armo-scan-role-cross-with_customer-12345678","externalID":""}',
                '{"level":"error","msg":"Request failed","Request body":"{\\"name\\":\\"systest-1-cspm-bad\\"}"}',
                '{"level":"error","msg":"Something else"}',
            ]
        )
        lines = _find_expected_negative_log_lines(error_logs, markers, max_lines=10)
        self.assertGreaterEqual(len(lines), 2)
        self.assertTrue(any("12345678" in ln for ln in lines))
        self.assertTrue(any("cspm-bad" in ln for ln in lines))


if __name__ == "__main__":
    unittest.main()


