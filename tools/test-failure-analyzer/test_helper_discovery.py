#!/usr/bin/env python3
"""
Unit tests for helper file discovery in extract_call_chain.py.

These tests verify that helper files like *_helpers.go and *_utils.go
are correctly identified and discovered in call chain extraction.
"""

import unittest
from extract_call_chain import is_helper_file, discover_helper_chunks_for_package


class TestIsHelperFile(unittest.TestCase):
    """Test cases for is_helper_file function."""
    
    def test_helpers_suffix(self):
        """Test *_helpers.go pattern."""
        self.assertTrue(is_helper_file("ticket_create_helpers.go"))
        self.assertTrue(is_helper_file("httphandlerv2/ticket_create_helpers.go"))
        self.assertTrue(is_helper_file("auth_helpers.go"))
    
    def test_helper_suffix(self):
        """Test *_helper.go pattern."""
        self.assertTrue(is_helper_file("ticket_helper.go"))
        self.assertTrue(is_helper_file("bl/ticket_helper.go"))
    
    def test_utils_suffix(self):
        """Test *_utils.go pattern."""
        self.assertTrue(is_helper_file("string_utils.go"))
        self.assertTrue(is_helper_file("utils/string_utils.go"))
    
    def test_util_suffix(self):
        """Test *_util.go pattern."""
        self.assertTrue(is_helper_file("json_util.go"))
    
    def test_exact_helpers_go(self):
        """Test exact helpers.go match."""
        self.assertTrue(is_helper_file("helpers.go"))
        self.assertTrue(is_helper_file("pkg/helpers.go"))
    
    def test_exact_utils_go(self):
        """Test exact utils.go match."""
        self.assertTrue(is_helper_file("utils.go"))
        self.assertTrue(is_helper_file("internal/utils.go"))
    
    def test_not_helper_handler(self):
        """Test that handlers are not detected as helpers."""
        self.assertFalse(is_helper_file("handler.go"))
        self.assertFalse(is_helper_file("cloudposture_handler.go"))
        self.assertFalse(is_helper_file("httphandlerv2/handler.go"))
    
    def test_not_helper_service(self):
        """Test that services are not detected as helpers."""
        self.assertFalse(is_helper_file("service.go"))
        self.assertFalse(is_helper_file("ticket_service.go"))
    
    def test_not_helper_repository(self):
        """Test that repositories are not detected as helpers."""
        self.assertFalse(is_helper_file("repository.go"))
        self.assertFalse(is_helper_file("user_repository.go"))
    
    def test_empty_path(self):
        """Test empty path returns False."""
        self.assertFalse(is_helper_file(""))
        self.assertFalse(is_helper_file(None))
    
    def test_case_sensitivity(self):
        """Test case handling (should be lowercase comparison)."""
        # These should match (case-insensitive)
        self.assertTrue(is_helper_file("HELPERS.GO"))
        self.assertTrue(is_helper_file("Utils.go"))
        self.assertTrue(is_helper_file("Ticket_Helpers.go"))


class TestDiscoverHelperChunksForPackage(unittest.TestCase):
    """Test cases for discover_helper_chunks_for_package function."""
    
    def setUp(self):
        """Set up test chunks."""
        self.test_chunks = [
            {
                "id": "chunk_1",
                "name": "handleTicket",
                "file": "httphandlerv2/ticket_handler.go",
                "package": "httphandlerv2",
                "_repo": "cadashboardbe"
            },
            {
                "id": "chunk_2",
                "name": "resolveIssueOwner",
                "file": "httphandlerv2/ticket_create_helpers.go",
                "package": "httphandlerv2",
                "_repo": "cadashboardbe"
            },
            {
                "id": "chunk_3",
                "name": "validateTicket",
                "file": "httphandlerv2/ticket_create_helpers.go",
                "package": "httphandlerv2",
                "_repo": "cadashboardbe"
            },
            {
                "id": "chunk_4",
                "name": "getServiceConfig",
                "file": "bl/config_utils.go",
                "package": "bl",
                "_repo": "cadashboardbe"
            },
            {
                "id": "chunk_5",
                "name": "processData",
                "file": "bl/processor.go",
                "package": "bl",
                "_repo": "cadashboardbe"
            },
            {
                "id": "chunk_6",
                "name": "externalHelper",
                "file": "external/helpers.go",
                "package": "external",
                "_repo": "other-repo"
            }
        ]
    
    def test_discover_helpers_by_package(self):
        """Test discovering helpers by package name."""
        helpers = discover_helper_chunks_for_package(
            package_name="httphandlerv2",
            directory="",
            all_chunks=self.test_chunks
        )
        
        # Should find 2 helper chunks from ticket_create_helpers.go
        self.assertEqual(len(helpers), 2)
        helper_names = {h["name"] for h in helpers}
        self.assertIn("resolveIssueOwner", helper_names)
        self.assertIn("validateTicket", helper_names)
    
    def test_discover_helpers_by_directory(self):
        """Test discovering helpers by directory."""
        helpers = discover_helper_chunks_for_package(
            package_name="",
            directory="httphandlerv2",
            all_chunks=self.test_chunks
        )
        
        # Should find helper chunks from httphandlerv2/
        self.assertEqual(len(helpers), 2)
    
    def test_discover_helpers_with_repo_filter(self):
        """Test discovering helpers with repo filter."""
        helpers = discover_helper_chunks_for_package(
            package_name="external",
            directory="",
            all_chunks=self.test_chunks,
            repo="other-repo"
        )
        
        # Should find 1 helper from external package in other-repo
        self.assertEqual(len(helpers), 1)
        self.assertEqual(helpers[0]["name"], "externalHelper")
    
    def test_discover_helpers_excludes_wrong_repo(self):
        """Test that repo filter excludes chunks from other repos."""
        helpers = discover_helper_chunks_for_package(
            package_name="external",
            directory="",
            all_chunks=self.test_chunks,
            repo="cadashboardbe"  # Filter for wrong repo
        )
        
        # Should find 0 helpers (external is in other-repo)
        self.assertEqual(len(helpers), 0)
    
    def test_discover_bl_utils(self):
        """Test discovering utils in bl package."""
        helpers = discover_helper_chunks_for_package(
            package_name="bl",
            directory="",
            all_chunks=self.test_chunks
        )
        
        # Should find config_utils.go helper
        self.assertEqual(len(helpers), 1)
        self.assertEqual(helpers[0]["name"], "getServiceConfig")
    
    def test_no_duplicates(self):
        """Test that duplicate chunk IDs are not returned."""
        # Add a duplicate chunk with same ID
        chunks_with_dup = self.test_chunks + [{
            "id": "chunk_2",  # Same ID as existing
            "name": "resolveIssueOwner_dup",
            "file": "httphandlerv2/ticket_create_helpers.go",
            "package": "httphandlerv2",
            "_repo": "cadashboardbe"
        }]
        
        helpers = discover_helper_chunks_for_package(
            package_name="httphandlerv2",
            directory="",
            all_chunks=chunks_with_dup
        )
        
        # Should still only return 2 unique chunks
        self.assertEqual(len(helpers), 2)
    
    def test_empty_chunks_list(self):
        """Test with empty chunks list."""
        helpers = discover_helper_chunks_for_package(
            package_name="httphandlerv2",
            directory="",
            all_chunks=[]
        )
        
        self.assertEqual(len(helpers), 0)


class TestHelperIntegration(unittest.TestCase):
    """Integration tests for helper discovery in call chain context."""
    
    def test_ticket_create_helpers_would_be_found(self):
        """
        Verify that ticket_create_helpers.go would be found for httphandlerv2 handlers.
        
        This is the specific case that caused the test failure where
        resolveIssueOwner() was missing from LLM context.
        """
        # Simulate the handler chunk
        handler_chunk = {
            "id": "handler_chunk_1",
            "name": "cloudPostureControlsHandler",
            "file": "httphandlerv2/cloudposture_handler.go",
            "package": "httphandlerv2",
            "_repo": "cadashboardbe"
        }
        
        # Simulate helper chunks
        helper_chunks = [
            {
                "id": "helper_chunk_1",
                "name": "resolveIssueOwner",
                "file": "httphandlerv2/ticket_create_helpers.go",
                "package": "httphandlerv2",
                "_repo": "cadashboardbe"
            }
        ]
        
        # Verify the helper file is detected
        self.assertTrue(is_helper_file("httphandlerv2/ticket_create_helpers.go"))
        
        # Verify it would be discovered for the handler's package
        all_chunks = [handler_chunk] + helper_chunks
        discovered = discover_helper_chunks_for_package(
            package_name="httphandlerv2",
            directory="httphandlerv2",
            all_chunks=all_chunks,
            repo="cadashboardbe"
        )
        
        self.assertEqual(len(discovered), 1)
        self.assertEqual(discovered[0]["name"], "resolveIssueOwner")


if __name__ == "__main__":
    unittest.main()

