#!/usr/bin/env python3
"""
Unit tests for extract_test_run_id.py
"""

import unittest
from extract_test_run_id import extract_test_run_id


class TestExtractTestRunID(unittest.TestCase):
    
    def test_pattern1_primary(self):
        """Test primary pattern: 'Test Run ID updated to cluster name: <name>'"""
        logs = """
        Some log output
        Test Run ID updated to cluster name: cluster-abc123
        More log output
        """
        result = extract_test_run_id(logs)
        self.assertEqual(result, "cluster-abc123")
    
    def test_pattern1_with_spaces(self):
        """Test primary pattern with extra spaces"""
        logs = "Test Run ID updated to cluster name:  my-cluster-name  "
        result = extract_test_run_id(logs)
        self.assertEqual(result, "my-cluster-name")
    
    def test_pattern2_fallback(self):
        """Test fallback pattern: 'Test Run ID: <id>'"""
        logs = """
        Some log output
        Test Run ID: test-run-456
        More log output
        """
        result = extract_test_run_id(logs)
        self.assertEqual(result, "test-run-456")
    
    def test_pattern2_case_insensitive(self):
        """Test fallback pattern is case insensitive"""
        logs = "test run id: TEST-123"
        result = extract_test_run_id(logs)
        self.assertEqual(result, "TEST-123")
    
    def test_pattern1_takes_precedence(self):
        """Test that pattern 1 takes precedence over pattern 2"""
        logs = """
        Test Run ID updated to cluster name: cluster-primary
        Test Run ID: fallback-id
        """
        result = extract_test_run_id(logs)
        self.assertEqual(result, "cluster-primary")
    
    def test_no_match(self):
        """Test when no pattern matches"""
        logs = "Some random log output without test run ID"
        result = extract_test_run_id(logs)
        self.assertIsNone(result)
    
    def test_empty_logs(self):
        """Test with empty logs"""
        result = extract_test_run_id("")
        self.assertIsNone(result)
    
    def test_multiline_logs(self):
        """Test with multiline logs"""
        logs = """
        Step 1: Starting test
        Step 2: Setting up cluster
        Test Run ID updated to cluster name: multi-line-cluster
        Step 3: Running tests
        """
        result = extract_test_run_id(logs)
        self.assertEqual(result, "multi-line-cluster")
    
    def test_with_colon_in_name(self):
        """Test that it handles names with colons correctly"""
        logs = "Test Run ID updated to cluster name: cluster:with:colons"
        result = extract_test_run_id(logs)
        self.assertEqual(result, "cluster:with:colons")
    
    def test_with_underscores(self):
        """Test with underscores in cluster name"""
        logs = "Test Run ID updated to cluster name: cluster_name_123"
        result = extract_test_run_id(logs)
        self.assertEqual(result, "cluster_name_123")


if __name__ == '__main__':
    unittest.main()

