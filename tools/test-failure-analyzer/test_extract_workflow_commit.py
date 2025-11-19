#!/usr/bin/env python3
"""
Unit tests for extract_workflow_commit.py
"""

import unittest
from extract_workflow_commit import (
    extract_commit_from_logs,
    parse_run_url
)


class TestExtractWorkflowCommit(unittest.TestCase):
    
    def test_extract_from_logs_head_pattern(self):
        """Test extracting commit from 'HEAD is now at' pattern"""
        logs = """
        Running actions/checkout@v4
        HEAD is now at 7e920e4d90e390f2d2f8736e8608ea4c8647a4bf
        """
        result = extract_commit_from_logs(logs)
        self.assertEqual(result, "7e920e4d90e390f2d2f8736e8608ea4c8647a4bf")
    
    def test_extract_from_logs_checkout_pattern(self):
        """Test extracting commit from 'Checking out' pattern"""
        logs = "Checking out 7e920e4d90e390f2d2f8736e8608ea4c8647a4bf"
        result = extract_commit_from_logs(logs)
        self.assertEqual(result, "7e920e4d90e390f2d2f8736e8608ea4c8647a4bf")
    
    def test_extract_from_logs_commit_pattern(self):
        """Test extracting commit from 'commit' pattern"""
        logs = "commit 7e920e4d90e390f2d2f8736e8608ea4c8647a4bf"
        result = extract_commit_from_logs(logs)
        self.assertEqual(result, "7e920e4d90e390f2d2f8736e8608ea4c8647a4bf")
    
    def test_extract_from_logs_standalone_sha(self):
        """Test extracting standalone SHA"""
        logs = "Some log text 7e920e4d90e390f2d2f8736e8608ea4c8647a4bf more text"
        result = extract_commit_from_logs(logs)
        self.assertEqual(result, "7e920e4d90e390f2d2f8736e8608ea4c8647a4bf")
    
    def test_extract_from_logs_case_insensitive(self):
        """Test that extraction is case insensitive"""
        logs = "HEAD is now at 7E920E4D90E390F2D2F8736E8608EA4C8647A4BF"
        result = extract_commit_from_logs(logs)
        self.assertEqual(result.upper(), "7E920E4D90E390F2D2F8736E8608EA4C8647A4BF")
    
    def test_extract_from_logs_no_match(self):
        """Test when no commit is found"""
        logs = "Some random log output without commit SHA"
        result = extract_commit_from_logs(logs)
        self.assertIsNone(result)
    
    def test_extract_from_logs_empty(self):
        """Test with empty logs"""
        result = extract_commit_from_logs("")
        self.assertIsNone(result)
    
    def test_parse_run_url_valid(self):
        """Test parsing valid GitHub Actions run URL"""
        url = "https://github.com/armosec/shared-workflows/actions/runs/123456789"
        repo, run_id = parse_run_url(url)
        self.assertEqual(repo, "armosec/shared-workflows")
        self.assertEqual(run_id, "123456789")
    
    def test_parse_run_url_invalid(self):
        """Test parsing invalid URL"""
        url = "https://github.com/armosec/shared-workflows"
        repo, run_id = parse_run_url(url)
        self.assertIsNone(repo)
        self.assertIsNone(run_id)
    
    def test_parse_run_url_with_trailing_slash(self):
        """Test parsing URL with trailing slash"""
        url = "https://github.com/armosec/shared-workflows/actions/runs/123456789/"
        repo, run_id = parse_run_url(url)
        self.assertEqual(repo, "armosec/shared-workflows")
        self.assertEqual(run_id, "123456789")


if __name__ == '__main__':
    unittest.main()

