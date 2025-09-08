from tests_scripts.accounts.accounts import Accounts
from systest_utils import Logger
import os
import random
from infrastructure import aws
from .accounts import extract_parameters_from_url
from typing import List, Tuple
from .connect import REGION_SYSTEM_TEST
from .accounts import VULNSCAN_FEATURE_NAME



expected_instances_ids = ["i-035d6cba3ed6fa6cf", "i-0424907c0f6cd8c46", "i-075afeac250be212c"]
test_aws_account_id = "371864305487"

SMAPSHOT_TAG_NAME = "armo:secure:vulnscan:instance-scan-id"





class CloudVulnScan(Accounts):
    def __init__(self, test_obj=None, backend=None, kubernetes_obj=None, test_driver=None):
        super().__init__(test_driver=test_driver, test_obj=test_obj, backend=backend, kubernetes_obj=kubernetes_obj)

        self.skip_apis_validation = False
        self.cspm_vulnscan_stack_name = None
        self.cspm_vulnscan_external_id = None
        self.cspm_vulnscan_cloud_account_name = None
        self.test_cloud_accounts_guids = []



    def start(self):
        """
        Agenda:
        1. Init AwsManager
        2. Create cspm vulnscan stack
        3. Connect cspm vulnscan new account
        4. Validate hosts list
        5. Validate host scan
        6. Validate host details
        7. Validate hosts list filters
        8. Validate hosts uniquevalues
        9. Validate hosts vulnerabilities
        10. Validate hosts vulnerabilities uniquevalues
        11. Validate hosts components
        12. Validate hosts components uniquevalues
        13. Delete cspm vulnscan feature and validate
       
        """

        assert self.backend is not None, f'the test {self.test_driver.test_name} must run with backend'

        stack_region = REGION_SYSTEM_TEST
        # generate random number for cloud account name for uniqueness
        self.test_identifer_rand = str(random.randint(10000000, 99999999))

        Logger.logger.info('Stage 1: Init cloud formation manager')
        aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID_CLOUD_VULN_SCAN_TESTS")
        aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY_CLOUD_VULN_SCAN_TESTS")
    
        
        self.aws_manager = aws.AwsManager(stack_region, 
                                                  aws_access_key_id=aws_access_key_id, 
                                                  aws_secret_access_key=aws_secret_access_key)
        
        Logger.logger.info('Stage 2: Create cspm vulnscan stack') 
        self.cspm_vulnscan_stack_name = "systest-" + self.test_identifer_rand + "-cspm-vulnscan"
        stack_link, external_id = self.get_and_validate_vulnscan_link_with_external_id(stack_region) 
        self.cspm_vulnscan_external_id = external_id       
        _, template_url, _, parameters = extract_parameters_from_url(stack_link)
        Logger.logger.info(f"Creating stack {self.cspm_vulnscan_stack_name} with template {template_url} and parameters {parameters}")
        test_arn = self.create_stack_cspm(self.cspm_vulnscan_stack_name, template_url, parameters)
        account_id = aws.extract_account_id(test_arn)
        Logger.logger.info(f"Created cspm stack {self.cspm_vulnscan_stack_name} with account id {account_id} and arn {test_arn}")

        self.cspm_vulnscan_cloud_account_name = "systest-" + self.test_identifer_rand + "-cspm-vulnscan"


        Logger.logger.info('Stage 3: Connect cspm vulnscan new account') 
        cloud_account_guid = self.connect_cspm_vulnscan_new_account(stack_region, account_id, test_arn, self.cspm_vulnscan_cloud_account_name, self.cspm_vulnscan_external_id)
        self.test_cloud_accounts_guids.append(cloud_account_guid)

        Logger.logger.info('Stage 4: Wait for cspm vulnscan scan to complete successfully')
        result, _ = self.wait_for_report(
            self.validate_hosts_list,
            timeout=840,
            sleep_interval=20,
            cloud_account_guid=cloud_account_guid,
            expected_instances_ids=expected_instances_ids
        )

        instance_hashes = result[0]
        instance_scan_ids = result[1]

        Logger.logger.info(f"Instance scan ids: {instance_scan_ids}")
        Logger.logger.info(f"Instance hashes: {instance_hashes}")

        Logger.logger.info('Stage 5: Validate hosts list filters')
        self.validate_hosts_list_filters(cloud_account_guid, expected_instances_ids)

        Logger.logger.info('Stage 6: Validate host scan')
        self.validate_host_scan(instance_hashes)

        Logger.logger.info('Stage 7: Validate host details')
        self.validate_host_details(cloud_account_guid, instance_hashes)

        Logger.logger.info('Stage 8: Validate hosts uniquevalues')
        self.validate_hosts_uniquevalues(cloud_account_guid, expected_instances_ids)

        Logger.logger.info('Stage 9: Validate hosts vulnerabilities')
        self.validate_hosts_vulnerabilities(cloud_account_guid, expected_instances_ids, instance_hashes)

        Logger.logger.info('Stage 10: Validate hosts vulnerabilities uniquevalues')
        self.validate_hosts_vulnerabilities_uniquevalues(cloud_account_guid, expected_instances_ids)

        Logger.logger.info('Stage 11: Validate hosts components')
        self.validate_hosts_components(cloud_account_guid, test_aws_account_id, instance_hashes)

        Logger.logger.info('Stage 12: Validate hosts components uniquevalues')
        self.validate_hosts_components_uniquevalues(cloud_account_guid, test_aws_account_id) 

        Logger.logger.info('Stage 13: Delete cspm vulnscan feature and validate')
        self.delete_and_validate_account_feature(cloud_account_guid, VULNSCAN_FEATURE_NAME)

        Logger.logger.info('Stage 14: Validate snapshots deleted')
        self.validate_snapshots_deleted(instance_scan_ids)


        return self.cleanup()

    def cleanup(self, **kwargs):
        if self.cspm_vulnscan_stack_name is not None:
            self.aws_manager.delete_stack(self.cspm_vulnscan_stack_name)
            Logger.logger.info(f"Deleted stack {self.cspm_vulnscan_stack_name}")
        return super().cleanup(**kwargs)

    def validate_snapshots_deleted(self, instance_scan_ids: List[str]):
        for instance_scan_id in instance_scan_ids:
            tag = {
                SMAPSHOT_TAG_NAME: instance_scan_id
            }
            snapshot_id = self.aws_manager.check_snapshot_by_tags(tag)
            assert snapshot_id == "", f"Snapshot {instance_scan_id} not deleted"
        Logger.logger.info(f"All snapshots deleted for instance scan ids {instance_scan_ids}")

    
    def validate_hosts_list(self, cloud_account_guid: str, expected_instances_ids: List[str]) -> Tuple[List[str], List[str]]:
        instance_hashes = []
        instance_scan_ids = []
        body = {
            "pageSize": 50,
            "pageNum": 1,
            "orderBy": "hostID:asc",
            "innerFilters": [
                {
                    "cloudAccountGUID": cloud_account_guid
                }
            ]
        }

        response = self.backend.get_vuln_v2_hosts(body)
        assert response is not None, "Response is None"
        assert len(response) > 0, "Response is empty"
        assert len(response) == len(expected_instances_ids), f"Expected {len(expected_instances_ids)} hosts, got {len(response)}"
        Logger.logger.info(f"Number of Hosts found: {len(response)}")
        for host in response:
            instance_hashes.append(host["instanceHash"])
            instance_scan_ids.append(host["instanceScanId"])
        
        return instance_hashes, instance_scan_ids
    
    def validate_host_scan(self, instance_hashes: List[str]) -> List[str]:
        # scan now only scans failed hosts - since we don't simulate such in test we just check that the endpoint is working

        Logger.logger.info(f"Validating host scan for {instance_hashes}") 
        body = instance_hashes
        response = self.backend.get_vuln_v2_host_scan(body)
        assert response is not None, f"Response is None for Host {instance_hashes}"

        Logger.logger.info(f"Validating host scan for empty list") 
        body = []
        response = self.backend.get_vuln_v2_host_scan(body)
        assert response is not None, f"Response is None for Host {instance_hashes}"
      
        
    
    def validate_host_details(self, cloud_account_guid: str, instance_hashes: List[str]) -> List[str]:
        for instance_hash in instance_hashes:
            body = {
                "pageSize": 50,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "instanceHash": instance_hash,
                        "cloudAccountGUID": cloud_account_guid
                    }
                ]
            }
            response = self.backend.get_vuln_v2_host_details(body)
            assert response is not None, f"Response is None for Host {instance_hash}"
            assert response["instanceHash"] == instance_hash, f"Expected instance hash {instance_hash}, got {response['instanceHash']}"
            Logger.logger.info(f"Host details found for Host {instance_hash}")


    def validate_hosts_list_filters(self, cloud_account_guid: str, expected_instances_ids: List[str]):
        Logger.logger.info(f"Validating expected instances ids: {expected_instances_ids}")
        for instance_id in expected_instances_ids:
            body = {
                "pageSize": 50,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "hostID": instance_id,
                        "cloudAccountGUID": cloud_account_guid
                    }
                ]
            }

            response = self.backend.get_vuln_v2_hosts(body)
            assert response is not None, "Response is None"
            assert len(response) > 0, f"Response is empty for Host {instance_id}"
            assert len(response) == 1, f"Host {instance_id} not found"
            Logger.logger.info(f"Host {instance_id} found")
    
        last_response = response[0]
        Logger.logger.info(f"Validating hosts list filters for host {last_response['hostID']}")

        cve = None
        severity = None
        for cveSeverity in last_response["severityStats"]:
            if len(last_response["severityStats"][cveSeverity]) > 0:
                cve  = last_response["severityStats"][cveSeverity][0]
                severity = cveSeverity
                break
        
        assert cve is not None, f"No CVE found for Host {last_response['hostID']}"
        assert severity is not None, f"No Severity found for Host {last_response['hostID']}"
            
        body = {
                "pageSize": 50,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "accountID": last_response["accountID"],
                        "hostID": last_response["hostID"],
                        "hostType": last_response["hostType"],
                        "privateIpAddress": last_response["privateIpAddress"],
                        "region": last_response["region"],
                        "name": cve,
                        "severity": severity
                    }
                ]
            }

        response = self.backend.get_vuln_v2_hosts(body)
        assert response is not None, f"Response is None for Host {last_response['hostID']}"
        assert len(response) == 1, f"Host {last_response['hostID']} not found"
        Logger.logger.info(f"Host {last_response['hostID']} found")

        
    def validate_hosts_uniquevalues(self, cloud_account_guid: str, expected_instances_ids: List[str]):
        fields = [
            "hostType",
            "privateIpAddress",
            "hostID|hostType|provider",
            "region"
        ]

        for instance_id in expected_instances_ids:
            body = {
                "pageSize": 50,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "hostID": instance_id,
                        "cloudAccountGUID": cloud_account_guid
                    }
                ]
            }

            for field in fields:
                body["fields"] = {field:""}
                response = self.backend.get_vuln_v2_host_uniquevalues(body)
                assert response is not None, f"Response is None for {field} for Host {instance_id}"  
                assert len(response) > 0, f"Response is empty for {field} for Host {instance_id}"
                Logger.logger.info(f"Found hosts unique values for {field}: {response} for Host {instance_id}")
            
        Logger.logger.info(f"Hosts unique values validation completed successfully for all Hosts {expected_instances_ids}")
    
    def validate_hosts_vulnerabilities(self, cloud_account_guid: str, expected_instances_ids: List[str], instance_hashes: List[str]):
        for instance_id in expected_instances_ids:
            body = {
                "pageSize": 50,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "hostID": instance_id,
                        "cloudAccountGUID": cloud_account_guid
                    }
                ]
            }

            response = self.backend.get_vulns_v2(body)
            assert response is not None, f"Response is None for Host {instance_id}" 
            assert len(response) > 0, f"Response is empty for Host {instance_id}" 
            Logger.logger.info(f"Hosts vulnerabilities found for Host {instance_id}")
        
        Logger.logger.info(f"Hosts vulnerabilities validation completed successfully for all Hosts {expected_instances_ids}")


        # checking for vulnerabilities by instance hash
        for instance_hash in instance_hashes:
            body = {
                "pageSize": 50,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "instanceHash": instance_hash,
                        "cloudAccountGUID": cloud_account_guid,
                        "isRelevant": "Yes"
                    }
                ]
            }
            Logger.logger.info(f"Validating hosts vulnerabilities for instance hash {instance_hash} with relevant yes")
            response = self.backend.get_vulns_v2(body)
            assert response is not None, f"Response is None for Host {instance_hash}"
            assert len(response) > 0, f"Response is empty for Host {instance_hash}"
            Logger.logger.info(f"Hosts vulnerabilities found for Host {instance_hash}")

            Logger.logger.info(f"Validating hosts vulnerabilities for instance hash {instance_hash} with relevant no")
            body["innerFilters"][0]["isRelevant"] = "No"
            response = self.backend.get_vulns_v2(body)
            assert response is not None, f"Response is None for Host {instance_hash}"
            assert len(response) == 0, f"Response is not empty for Host {instance_hash} with relevant no"
            Logger.logger.info(f"Hosts vulnerabilities found: {len(response)} for Host {instance_hash}")
        
        Logger.logger.info(f"Hosts vulnerabilities validation completed successfully for all Hosts {instance_hashes}")


    def validate_hosts_vulnerabilities_uniquevalues(self, cloud_account_guid: str, expected_instances_ids: List[str]):
        fields = [
            "hostID|hostType|provider",
            "region"
        ]
        
        for instance_id in expected_instances_ids:
            body = {
                "pageSize": 50,
                "pageNum": 1,
                "innerFilters": [
                    {
                        "hostID": instance_id,
                        "cloudAccountGUID": cloud_account_guid
                    }
                ]
            }

            for field in fields:
                body["fields"] = {field:""}
                response = self.backend.get_vuln_v2_vulnerabilities_uniquevalues(body)
                assert response is not None, f"Response is None for {field} for Host {instance_id}"
                assert len(response) > 0, f"Response is empty for {field} for Host {instance_id}"
                Logger.logger.info(f"Found hosts vulnerabilities unique values for {field}: {response} for Host {instance_id}")
        
        Logger.logger.info(f"Hosts vulnerabilities unique values validation completed successfully for all Hosts {expected_instances_ids}")


    def validate_hosts_components(self, cloud_account_guid: str, aws_account_id: str, instance_hashes: List[str]):
        body = {
            "pageSize": 50,
            "pageNum": 1,
            "innerFilters": [
                {
                    "accountID": aws_account_id,
                    "cloudAccountGUID": cloud_account_guid
                }
            ]
        }

        Logger.logger.info(f"Validating hosts components for aws account {aws_account_id} with scope component")
        response = self.backend.get_vuln_v2_components(body, scope="component")
        assert response is not None, f"Response is None for Host {aws_account_id}"
        assert len(response) > 0, f"Response is empty for Host {aws_account_id}"
        Logger.logger.info(f"Hosts components found: {len(response)} for Host {aws_account_id}")


        for instance_hash in instance_hashes:
            Logger.logger.info(f"Validating hosts components for instance hash {instance_hash} with scope host and relevant yes")
            body["innerFilters"][0]["instanceHash"] = instance_hash
            body["innerFilters"][0]["isRelevant"] = "Yes"
            response = self.backend.get_vuln_v2_components(body, scope="host")
            assert response is not None, f"Response is None for Host {instance_hash}"
            assert len(response) > 0, f"Response is empty for Host {instance_hash}"
            Logger.logger.info(f"Hosts components found: {len(response)} for Host {instance_hash}")


            Logger.logger.info(f"Validating hosts components for instance hash {instance_hash} with scope host and relevant no")
            body["innerFilters"][0]["isRelevant"] = "No"
            response = self.backend.get_vuln_v2_components(body, scope="host")
            assert response is not None, f"Response is None for Host {instance_hash}"
            assert len(response) == 0, f"Response is not empty for Host {instance_hash} with relevant no"
            Logger.logger.info(f"Hosts components found: {len(response)} for Host {instance_hash}")

        

    
    def validate_hosts_components_uniquevalues(self, cloud_account_guid: str, aws_account_id: str):
        fields = [
            "accountID|accountName|provider",
            "region"
        ]
        
        body = {
            "pageSize": 50,
            "pageNum": 1,
            "innerFilters": [
                {
                    "accountID": aws_account_id,
                    "cloudAccountGUID": cloud_account_guid
                }
            ]
        }
        

        for field in fields:
            body["fields"] = {field:""}
            response = self.backend.get_vuln_v2_component_uniquevalues(body)
            assert response is not None, f"Response is None for {field} for Host {aws_account_id}"
            assert len(response) > 0, f"Response is empty for {field} for Host {aws_account_id}"
            Logger.logger.info(f"Found hosts components unique values for {field}: {response} for aws account {aws_account_id}")
        
        Logger.logger.info(f"Hosts components unique values validation completed successfully for aws account {aws_account_id}")
