from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

# Constants for test configuration
FRAMEWORKS_CONFIG = {
    "cis_1.4": 50,
    "cis_1.5": 52,
    "cis_2.0": 52,
    "cis_3.0": 51,
    "fedramp_moderate_revision_4": 62,
    "gdpr": 3,
    "hipaa": 31,
    "mitre_attack": 43,
    "nist_800_53_revision_5": 263,
    "pci_3.2.1": 13,
    "soc2": 53,
    "iso27001_2022": 100
}

DEFAULT_TEST_CONFIG = {
    "framework": "cis_3.0",
    "control_name": "Ensure IAM instance roles are used for AWS resource access from instances",
    "rule_name": "Ensure IAM instance roles are used for AWS resource access from instances",
    "rule_hash": "025a0dc9-33c9-77d0-8554-7ca68ee1b307",
    "rule_id": "ec2_instance_profile_attached",
    "check_type": "AUTOMATED",
    "severity": "medium",
    "status": "FAIL",
    "resource_hash": "00702d59-a435-c9cf-0860-c05098c4f23e",
    "resource_name" : "i-0df4d10d2f2ae99f7",
    "resource_type" :"ec2",
    "resource_id" : "arn:aws:ec2:eu-west-1:686255980207:instance/i-0df4d10d2f2ae99f7"
}

# Pydantic models for API responses
class SeverityCount(BaseModel):
    Critical: int
    High: int
    Medium: int
    Low: int

class ComplianceAccountResponse(BaseModel):
    reportGUID: str
    criticalSeverityResources: int
    highSeverityResources: int
    mediumSeverityResources: int
    lowSeverityResources: int

class FrameworkCord(BaseModel):
    reportGUID: str
    complianceScore: float
    timestamp: datetime

class Framework(BaseModel):
    frameworkName: str
    complianceScore: float
    cords: List[FrameworkCord]

class ComplianceFrameworkOverTime(BaseModel):
    cloudAccountGUID: str
    provider: str
    frameworks: List[Framework]

class ComplianceFramework(BaseModel):
    name: str
    reportGUID: str
    failedControls: int
    complianceScorev1: float
    timestamp: datetime

class ComplianceControl(BaseModel):
    reportGUID: str
    frameworkName: str
    section: str
    cloudControlName: str
    status: str
    severity: str
    checkType: str
    affectedResourcesCount: int
    failedResourcesCount: int
    totalScannedResourcesCount: int
    acceptedResourcesCount: int
    complianceScore: float
    cloudControlHash: str
    exceptionApplied: bool
    tickets: Optional[List[Dict]] = None

class ComplianceRuleSummary(BaseModel):
    cloudCheckName: str
    cloudCheckHash: str
    cloudCheckID: str
    status: str
    severity: str
    checkType: str
    affectedControls: List[str]
    totalScannedResourcesCount: int
    failedResourcesCount: int
    acceptedResourcesCount: int
    exceptionApplied: bool
    tickets: Optional[List[Dict]] = None

class ComplianceResourceToCheck(BaseModel):
    reportGUID : str
    severity : str
    checkType : str
    status : str
    cloudResourceHash : str
    cloudResourceName : str
    cloudResourceID : str
    cloudResourceType : str
    cloudCheckName : str # rule name
    cloudCheckHash : str # rule hash
    cloudCheckID : str # rule id
    exceptionApplied: bool
    tickets: Optional[List[Dict]] = None

class ComplianceControlWithChecks(ComplianceControl):
    rules: List[ComplianceResourceToCheck]

class ComplianceResourceSummaries(BaseModel):
    reportGUID : str
    cloudAccountGUID : str
    provider : str
    cloudResourceName : str
    cloudResourceID : str
    cloudResourceType : str
    cloudResourceHash : str
    cloudResourceRegion : str
    frameworkName : str
    failedControlsCount : int
    passedControlsCount : int
    manualControlsCount : int
    provider : str

    lowSeverityControls : int
    mediumSeverityControls : int
    highSeverityControls : int
    criticalSeverityControls : int

    failedControlsCount : int
    containsAcceptedControlCount : int
    passedControlsCount : int
    manualControlsCount : int
    tickets: Optional[List[Dict]] = None

def get_expected_accounts_response(last_success_scan_id: str) -> Dict:
    """Get expected response for accounts API."""
    return {
        "reportGUID": last_success_scan_id,
        "criticalSeverityResources": None,  # Will be compared with actual severity count
        "highSeverityResources": None,      # Will be compared with actual severity count
        "mediumSeverityResources": None,    # Will be compared with actual severity count
        "lowSeverityResources": None        # Will be compared with actual severity count
    }

def get_expected_framework_response(last_success_scan_id: str) -> Dict:
    """Get expected response for framework API."""
    return {
        "name": None,  # Will be checked against FRAMEWORKS_CONFIG
        "reportGUID": last_success_scan_id,
        "failedControls": None,  # Will be checked > 0
        "complianceScorev1": None,  # Will be checked > 0
        "timestamp": None  # Will be checked within time window
    }

def get_expected_framework_over_time_response(cloud_account_guid: str, last_success_scan_id: str) -> Dict:
    """Get expected response for framework over time API."""
    return {
        "cloudAccountGUID": cloud_account_guid,
        "provider": "aws",
        "frameworks": [{
            "frameworkName": None,  # Will be checked against FRAMEWORKS_CONFIG
            "complianceScore": None,  # Will be checked > 0
            "cords": [{
                "reportGUID": last_success_scan_id,
                "complianceScore": None,  # Will be checked > 0
                "timestamp": None  # Will be checked within time window
            }]
        }]
    }

def get_expected_control_response(with_accepted_resources: bool = False) -> Dict:
    """Get expected response for control API."""
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "frameworkName": DEFAULT_TEST_CONFIG["framework"],
        "section": "",  # This will be checked to be non-empty
        "cloudControlName": DEFAULT_TEST_CONFIG["control_name"],
        "status": "ACCEPT" if with_accepted_resources else DEFAULT_TEST_CONFIG["status"],
        "severity":"none" if with_accepted_resources else DEFAULT_TEST_CONFIG["severity"],
        "checkType": DEFAULT_TEST_CONFIG["check_type"],
        "affectedResourcesCount": 1,
        "failedResourcesCount": 0 if with_accepted_resources else 1,
        "totalScannedResourcesCount": 1,
        "acceptedResourcesCount": 1 if with_accepted_resources else 0,
        "complianceScore": 100.0 if with_accepted_resources else 0.0,
        "exceptionApplied": True if with_accepted_resources else False
    }

def get_expected_rules_response(with_accepted_resources: bool = False) -> Dict:
    """Get expected response for check API."""
    return {
        "cloudCheckName": DEFAULT_TEST_CONFIG["rule_name"],
        "cloudCheckHash": DEFAULT_TEST_CONFIG["rule_hash"],
        "cloudCheckID": DEFAULT_TEST_CONFIG["rule_id"],
        "status": "ACCEPT" if with_accepted_resources else DEFAULT_TEST_CONFIG["status"],
        "severity": "none" if with_accepted_resources else DEFAULT_TEST_CONFIG["severity"],
        "checkType": DEFAULT_TEST_CONFIG["check_type"],
        "totalScannedResourcesCount": 1,
        "failedResourcesCount": 0 if with_accepted_resources else 1,
        "acceptedResourcesCount": 1 if with_accepted_resources else 0,
        "exceptionApplied": True if with_accepted_resources else False
    }

def get_expected_resources_under_check_response(with_accepted_resources: bool = False) -> Dict:
    """Get expected response for resource to check API."""
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "cloudResourceHash": DEFAULT_TEST_CONFIG["resource_hash"],
        "cloudResourceName": DEFAULT_TEST_CONFIG["resource_name"],
        "cloudResourceID": DEFAULT_TEST_CONFIG["resource_id"],
        "cloudResourceType": DEFAULT_TEST_CONFIG["resource_type"],
        "exceptionApplied": True if with_accepted_resources else False
    }

def get_expected_resource_summaries_response(with_accepted_resources: bool = False) -> Dict:
    """Get expected response for resource summaries API."""
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "cloudAccountGUID": "",  # This will be compared separately
        "provider": "aws",
        "cloudResourceName": DEFAULT_TEST_CONFIG["resource_name"],
        "cloudResourceID": DEFAULT_TEST_CONFIG["resource_id"],
        "cloudResourceHash": DEFAULT_TEST_CONFIG["resource_hash"],
        "cloudResourceType": DEFAULT_TEST_CONFIG["resource_type"],
        "frameworkName": DEFAULT_TEST_CONFIG["framework"],
        "failedControlsCount": 0 if with_accepted_resources else 1,
        "passedControlsCount": 1,
        "manualControlsCount": 0,
        "containsAcceptedControlCount": 1 if with_accepted_resources else 0,
        "criticalSeverityControls": 0,
        "highSeverityControls": 0,
        "mediumSeverityControls": 0 if with_accepted_resources else 1,
        "lowSeverityControls": 0,
    }

def get_expected_only_check_under_control_response(with_accepted_resources: bool = False) -> Dict:
    """Get expected response for control with checks API."""
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "exceptionApplied": True if with_accepted_resources else False,
        "severity": DEFAULT_TEST_CONFIG["severity"],
        "status": DEFAULT_TEST_CONFIG["status"],
        "checkType": DEFAULT_TEST_CONFIG["check_type"],
        "cloudCheckHash": DEFAULT_TEST_CONFIG["rule_hash"],
        "cloudCheckID": DEFAULT_TEST_CONFIG["rule_id"],
        "cloudCheckName": DEFAULT_TEST_CONFIG["rule_name"],
    }


def validate_timestamp_within_window(timestamp: datetime, window_minutes: int = 20) -> bool:
    """Validate that a timestamp is within the specified window from now."""
    now = datetime.now(datetime.timezone.utc)
    window = now - datetime.timedelta(minutes=window_minutes)
    return window <= timestamp <= now