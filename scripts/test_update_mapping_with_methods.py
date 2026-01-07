import unittest
from pathlib import Path


class TestUpdateMappingWithMethods(unittest.TestCase):
    def setUp(self):
        # Repo root is parent of scripts/
        self.repo_root = Path(__file__).parent.parent.resolve()

    def test_accounts_base_is_included_for_accounts_tests(self):
        from scripts.update_mapping_with_methods import find_base_classes

        test_file = self.repo_root / "tests_scripts" / "accounts" / "cloud_connect_cspm_single_aws.py"
        base_files = find_base_classes(test_file)
        self.assertIn("tests_scripts/accounts/accounts.py", base_files)

    def test_dynamic_backend_api_mapping_extracts_known_endpoints(self):
        from scripts.update_mapping_with_methods import build_api_method_mapping

        mapping = build_api_method_mapping(self.repo_root)

        # These are defined in infrastructure/backend_api.py and used by Accounts flows.
        self.assertIn("get_cloud_accounts", mapping)
        self.assertEqual(mapping["get_cloud_accounts"]["method"], "POST")
        self.assertEqual(mapping["get_cloud_accounts"]["path"], "/api/v1/accounts/cloud/list")

        self.assertIn("get_aws_regions", mapping)
        self.assertEqual(mapping["get_aws_regions"]["method"], "GET")
        self.assertEqual(mapping["get_aws_regions"]["path"], "/api/v1/accounts/aws/regions")

        # CSPM exception APIs should be discoverable (base path resolution is acceptable)
        self.assertIn("create_cspm_exception_req", mapping)
        self.assertEqual(mapping["create_cspm_exception_req"]["method"], "POST")
        self.assertEqual(mapping["create_cspm_exception_req"]["path"], "/api/v1/cloudposture/exceptions/new")

        self.assertIn("update_cspm_exception", mapping)
        self.assertEqual(mapping["update_cspm_exception"]["method"], "PUT")
        self.assertTrue(mapping["update_cspm_exception"]["path"].startswith("/api/v1/cloudposture/exceptions"))


if __name__ == "__main__":
    unittest.main()


