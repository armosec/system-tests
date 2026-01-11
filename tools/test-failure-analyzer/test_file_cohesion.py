#!/usr/bin/env python3
"""
Unit tests for file cohesion logic in build_llm_context.py.

File cohesion ensures that when any chunk from a helper file is selected,
all related functions from that file are included in the LLM context.
"""

import unittest
from typing import Dict, Any, List, Set

from build_llm_context import get_sibling_chunks_from_file
from extract_call_chain import is_helper_file


class TestIsHelperFile(unittest.TestCase):
    """Verify is_helper_file is correctly imported and works."""
    
    def test_helpers_go_suffix(self):
        self.assertTrue(is_helper_file("ticket_create_helpers.go"))
        self.assertTrue(is_helper_file("httphandlerv2/ticket_create_helpers.go"))
    
    def test_utils_go_suffix(self):
        self.assertTrue(is_helper_file("string_utils.go"))
        self.assertTrue(is_helper_file("utils/string_utils.go"))
    
    def test_non_helper_files(self):
        self.assertFalse(is_helper_file("handler.go"))
        self.assertFalse(is_helper_file("service.go"))
        self.assertFalse(is_helper_file("repository.go"))


class TestGetSiblingChunksFromFile(unittest.TestCase):
    """Test cases for get_sibling_chunks_from_file function."""
    
    def _make_chunk(self, chunk_id: str, file_path: str, name: str, code: str = "// code") -> Dict[str, Any]:
        """Helper to create a chunk dict."""
        return {
            "id": chunk_id,
            "file": file_path,
            "name": name,
            "code": code,
            "type": "function",
            "package": file_path.rsplit("/", 1)[0] if "/" in file_path else "",
        }
    
    def test_finds_siblings_in_code_index(self):
        """Should find other chunks from the same file in code_index."""
        code_index = {
            "chunks": [
                self._make_chunk("chunk1", "httphandlerv2/ticket_create_helpers.go", "func1"),
                self._make_chunk("chunk2", "httphandlerv2/ticket_create_helpers.go", "func2"),
                self._make_chunk("chunk3", "httphandlerv2/ticket_create_helpers.go", "func3"),
                self._make_chunk("chunk4", "httphandlerv2/other_file.go", "other_func"),
            ]
        }
        
        # Exclude chunk1 (already selected)
        exclude_ids = {"chunk1"}
        
        siblings = get_sibling_chunks_from_file(
            file_path="httphandlerv2/ticket_create_helpers.go",
            exclude_chunk_ids=exclude_ids,
            code_index=code_index,
        )
        
        # Should find chunk2 and chunk3, not chunk1 (excluded) or chunk4 (different file)
        self.assertEqual(len(siblings), 2)
        sibling_ids = {s["id"] for s in siblings}
        self.assertIn("chunk2", sibling_ids)
        self.assertIn("chunk3", sibling_ids)
        self.assertNotIn("chunk1", sibling_ids)
        self.assertNotIn("chunk4", sibling_ids)
    
    def test_finds_siblings_in_extra_indexes(self):
        """Should find siblings in extra_indexes (dependency repos)."""
        extra_indexes = {
            "some-dependency": {
                "chunks": [
                    self._make_chunk("dep_chunk1", "pkg/helpers.go", "helper1"),
                    self._make_chunk("dep_chunk2", "pkg/helpers.go", "helper2"),
                    self._make_chunk("dep_chunk3", "pkg/other.go", "other"),
                ]
            }
        }
        
        exclude_ids = {"dep_chunk1"}
        
        siblings = get_sibling_chunks_from_file(
            file_path="pkg/helpers.go",
            exclude_chunk_ids=exclude_ids,
            extra_indexes=extra_indexes,
        )
        
        self.assertEqual(len(siblings), 1)
        self.assertEqual(siblings[0]["id"], "dep_chunk2")
        self.assertEqual(siblings[0]["repo_name"], "some-dependency")
    
    def test_respects_max_per_file_cap(self):
        """Should not return more than max_per_file chunks."""
        code_index = {
            "chunks": [
                self._make_chunk(f"chunk{i}", "helpers.go", f"func{i}")
                for i in range(30)  # 30 chunks in one file
            ]
        }
        
        siblings = get_sibling_chunks_from_file(
            file_path="helpers.go",
            exclude_chunk_ids=set(),
            code_index=code_index,
            max_per_file=5,  # Cap at 5
        )
        
        self.assertEqual(len(siblings), 5)
    
    def test_handles_path_variations(self):
        """Should match files with different path prefixes."""
        code_index = {
            "chunks": [
                self._make_chunk("chunk1", "./httphandlerv2/helpers.go", "func1"),
                self._make_chunk("chunk2", "httphandlerv2/helpers.go", "func2"),
                self._make_chunk("chunk3", "/httphandlerv2/helpers.go", "func3"),
            ]
        }
        
        # Query with normalized path
        siblings = get_sibling_chunks_from_file(
            file_path="httphandlerv2/helpers.go",
            exclude_chunk_ids=set(),
            code_index=code_index,
        )
        
        # Should find all 3 (they're all the same file)
        self.assertEqual(len(siblings), 3)
    
    def test_returns_empty_for_nonexistent_file(self):
        """Should return empty list if file not found."""
        code_index = {
            "chunks": [
                self._make_chunk("chunk1", "other.go", "func1"),
            ]
        }
        
        siblings = get_sibling_chunks_from_file(
            file_path="nonexistent.go",
            exclude_chunk_ids=set(),
            code_index=code_index,
        )
        
        self.assertEqual(len(siblings), 0)
    
    def test_returns_empty_for_empty_path(self):
        """Should handle empty/None file path gracefully."""
        code_index = {"chunks": [self._make_chunk("chunk1", "file.go", "func1")]}
        
        self.assertEqual(get_sibling_chunks_from_file("", set(), code_index), [])
        self.assertEqual(get_sibling_chunks_from_file(None, set(), code_index), [])
    
    def test_sets_correct_source_and_priority(self):
        """Sibling chunks should have source='file_cohesion' and priority=1."""
        code_index = {
            "chunks": [
                self._make_chunk("chunk1", "helpers.go", "func1"),
            ]
        }
        
        siblings = get_sibling_chunks_from_file(
            file_path="helpers.go",
            exclude_chunk_ids=set(),
            code_index=code_index,
        )
        
        self.assertEqual(len(siblings), 1)
        self.assertEqual(siblings[0]["source"], "file_cohesion")
        self.assertEqual(siblings[0]["priority"], 1)
    
    def test_ticket_create_helpers_scenario(self):
        """
        Scenario test: If commonIssueRefResolver is selected from ticket_create_helpers.go,
        file cohesion should include resolveIssueOwner from the same file.
        """
        code_index = {
            "chunks": [
                self._make_chunk(
                    "httphandlerv2/ticket_create_helpers.go/commonIssueRefResolver",
                    "httphandlerv2/ticket_create_helpers.go",
                    "commonIssueRefResolver",
                    "func (r *commonIssueRefResolver) Resolve() {}"
                ),
                self._make_chunk(
                    "httphandlerv2/ticket_create_helpers.go/resolveIssueOwner",
                    "httphandlerv2/ticket_create_helpers.go",
                    "resolveIssueOwner",
                    "func (r *commonIssueRefResolver) resolveIssueOwner(reqOwner) {}"
                ),
                self._make_chunk(
                    "httphandlerv2/ticket_create_helpers.go/handleNewTicketSuccessCommon",
                    "httphandlerv2/ticket_create_helpers.go",
                    "handleNewTicketSuccessCommon",
                    "func handleNewTicketSuccessCommon() {}"
                ),
            ]
        }
        
        # Simulate: commonIssueRefResolver already selected
        exclude_ids = {"httphandlerv2/ticket_create_helpers.go/commonIssueRefResolver"}
        
        siblings = get_sibling_chunks_from_file(
            file_path="httphandlerv2/ticket_create_helpers.go",
            exclude_chunk_ids=exclude_ids,
            code_index=code_index,
        )
        
        # Should find resolveIssueOwner and handleNewTicketSuccessCommon
        self.assertEqual(len(siblings), 2)
        sibling_names = {s["name"] for s in siblings}
        self.assertIn("resolveIssueOwner", sibling_names)
        self.assertIn("handleNewTicketSuccessCommon", sibling_names)


if __name__ == "__main__":
    unittest.main()
