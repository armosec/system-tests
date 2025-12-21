from typing import Dict, List, Optional, Union
from pydantic import BaseModel
from datetime import datetime

# Constants for test configuration
PROVIDER_AWS = "aws"
PROVIDER_AZURE = "azure"
PROVIDER_GCP = "gcp"

FRAMEWORKS_CONFIG_AWS = {
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
    "pci_4.0": 0,  # Placeholder value (not validated, only key is checked)
    "soc2": 53,
    "iso27001_2022": 100
}

FRAMEWORKS_CONFIG_AZURE = {
    "cis_2.0": -1,
    "cis_2.1": -1,
    "cis_3.0": -1,
    "mitre_attack": -1,
    "iso27001_2022": -1,
    "pci_4.0": -1,
}

FRAMEWORKS_CONFIG_GCP = {
    "cis_2.0": -1,
    "cis_3.0": -1,
    "mitre_attack": -1,
    "iso27001_2022": -1,
    "pci_4.0": -1,
    "soc2": -1,
}

FRAMEWORKS_CONFIG_PROVIDER_MAP = {
    PROVIDER_AWS: FRAMEWORKS_CONFIG_AWS,
    PROVIDER_AZURE: FRAMEWORKS_CONFIG_AZURE,
    PROVIDER_GCP: FRAMEWORKS_CONFIG_GCP,
}

DEFAULT_TEST_CONFIG_AWS = {
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

DEFAULT_TEST_CONFIG_AZURE = {
    "framework": "cis_3.0",
    "control_name": "",
    "rule_name": "",
    "rule_hash": "",
    "rule_id": "",
    "check_type": "",
    "severity": "",
    "status": "",
    "resource_hash": "",
    "resource_name": "",
    "resource_type": "",
    "resource_id": "",
}

DEFAULT_TEST_CONFIG_GCP = {
    "framework": "cis_3.0",
    "control_name": "",
    "rule_name": "",
    "rule_hash": "",
    "rule_id": "",
    "check_type": "",
    "severity": "",
    "status": "",
    "resource_hash": "",
    "resource_name": "",
    "resource_type": "",
    "resource_id": "",
}

TEST_CONFIG_PROVIDER_MAP = {
    PROVIDER_AWS: DEFAULT_TEST_CONFIG_AWS,
    PROVIDER_AZURE: DEFAULT_TEST_CONFIG_AZURE,
    PROVIDER_GCP: DEFAULT_TEST_CONFIG_GCP,
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
        "name": None,  # Will be checked against FRAMEWORKS_CONFIG_PROVIDER_MAP[provider]
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
            "frameworkName": None,  # Will be checked against FRAMEWORKS_CONFIG_PROVIDER_MAP[provider]
            "complianceScore": None,  # Will be checked > 0
            "cords": [{
                "reportGUID": last_success_scan_id,
                "complianceScore": None,  # Will be checked > 0
                "timestamp": None  # Will be checked within time window
            }]
        }]
    }

def get_expected_aws_control_response(with_accepted_resources: bool = False) -> Dict:
    """Get expected response for control API (AWS-specific)."""
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "frameworkName": DEFAULT_TEST_CONFIG_AWS["framework"],
        "section": "",  # This will be checked to be non-empty
        "cloudControlName": DEFAULT_TEST_CONFIG_AWS["control_name"],
        "status": "ACCEPT" if with_accepted_resources else DEFAULT_TEST_CONFIG_AWS["status"],
        "severity":"none" if with_accepted_resources else DEFAULT_TEST_CONFIG_AWS["severity"],
        "checkType": DEFAULT_TEST_CONFIG_AWS["check_type"],
        "affectedResourcesCount": 1,
        "failedResourcesCount": 0 if with_accepted_resources else 1,
        "totalScannedResourcesCount": 1,
        "acceptedResourcesCount": 1 if with_accepted_resources else 0,
        "complianceScore": 100.0 if with_accepted_resources else 0.0,
        "exceptionApplied": True if with_accepted_resources else False
    }

def get_expected_aws_rules_response(with_accepted_resources: bool = False) -> Dict:
    """Get expected response for check API (AWS-specific)."""
    return {
        "cloudCheckName": DEFAULT_TEST_CONFIG_AWS["rule_name"],
        "cloudCheckHash": DEFAULT_TEST_CONFIG_AWS["rule_hash"],
        "cloudCheckID": DEFAULT_TEST_CONFIG_AWS["rule_id"],
        "status": "ACCEPT" if with_accepted_resources else DEFAULT_TEST_CONFIG_AWS["status"],
        "severity": "none" if with_accepted_resources else DEFAULT_TEST_CONFIG_AWS["severity"],
        "checkType": DEFAULT_TEST_CONFIG_AWS["check_type"],
        "totalScannedResourcesCount": 1,
        "failedResourcesCount": 0 if with_accepted_resources else 1,
        "acceptedResourcesCount": 1 if with_accepted_resources else 0,
        "exceptionApplied": True if with_accepted_resources else False
    }

def get_expected_aws_resources_under_check_response(with_accepted_resources: bool = False) -> Dict:
    """Get expected response for resource-to-check API (AWS-specific)."""
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "cloudResourceHash": DEFAULT_TEST_CONFIG_AWS["resource_hash"],
        "cloudResourceName": DEFAULT_TEST_CONFIG_AWS["resource_name"],
        "cloudResourceID": DEFAULT_TEST_CONFIG_AWS["resource_id"],
        "cloudResourceType": DEFAULT_TEST_CONFIG_AWS["resource_type"],
        "exceptionApplied": True if with_accepted_resources else False
    }

def get_expected_aws_resource_summaries_response(with_accepted_resources: bool = False) -> Dict:
    """Get expected response for resource-summaries API (AWS-specific)."""
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "cloudAccountGUID": "",  # This will be compared separately
        "provider": "aws",
        "cloudResourceName": DEFAULT_TEST_CONFIG_AWS["resource_name"],
        "cloudResourceID": DEFAULT_TEST_CONFIG_AWS["resource_id"],
        "cloudResourceHash": DEFAULT_TEST_CONFIG_AWS["resource_hash"],
        "cloudResourceType": DEFAULT_TEST_CONFIG_AWS["resource_type"],
        "frameworkName": DEFAULT_TEST_CONFIG_AWS["framework"],
        "failedControlsCount": 0 if with_accepted_resources else 1,
        "passedControlsCount": 1,
        "manualControlsCount": 0,
        "containsAcceptedControlCount": 1 if with_accepted_resources else 0,
        "criticalSeverityControls": 0,
        "highSeverityControls": 0,
        "mediumSeverityControls": 0 if with_accepted_resources else 1,
        "lowSeverityControls": 0,
    }

def get_expected_aws_only_check_under_control_response(with_accepted_resources: bool = False) -> Dict:
    """Get expected response for control-with-checks API (AWS-specific)."""
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "exceptionApplied": True if with_accepted_resources else False,
        "severity": DEFAULT_TEST_CONFIG_AWS["severity"],
        "status": DEFAULT_TEST_CONFIG_AWS["status"],
        "checkType": DEFAULT_TEST_CONFIG_AWS["check_type"],
        "cloudCheckHash": DEFAULT_TEST_CONFIG_AWS["rule_hash"],
        "cloudCheckID": DEFAULT_TEST_CONFIG_AWS["rule_id"],
        "cloudCheckName": DEFAULT_TEST_CONFIG_AWS["rule_name"],
    }


def validate_timestamp_within_window(timestamp: datetime, window_minutes: int = 20) -> bool:
    """Validate that a timestamp is within the specified window from now."""
    now = datetime.now(datetime.timezone.utc)
    window = now - datetime.timedelta(minutes=window_minutes)
    return window <= timestamp <= now


# Request and Response Models
class AwsStackResponse(BaseModel):
    """Response model for AWS stack operations."""
    stackLink: str
    externalID: str


class AwsMembersStackResponse(BaseModel):
    """Response model for AWS members stack operations."""
    s3TemplatePath: str
    externalID: str


class AWSOrgCreateCloudOrganizationAdminRequest(BaseModel):
    """Request model for creating AWS cloud organization with admin."""
    orgGUID: Union[str, None] = None
    stackRegion: str
    adminRoleArn: str
    adminRoleExternalID: Union[str, None] = None
    skipScan: bool = False


class CreateOrUpdateCloudOrganizationResponse(BaseModel):
    """Response model for creating or updating cloud organization."""
    guid: str


class ConnectCloudOrganizationMembersRequest(BaseModel):
    """Request model for connecting cloud organization members."""
    orgGUID: str
    features: List[str]
    memberRoleArn: Union[str, None] = None
    memberRoleExternalID: str
    stackRegion: str
    skipScan: bool = False


class UpdateCloudOrganizationMetadataRequest(BaseModel):
    """Request model for updating cloud organization metadata."""
    orgGUID: str
    newName: Union[str, None] = None
    featureNames: List[str] = []
    excludeAccounts: Union[List[str], None] = None
    
    def model_validate(self, data):
        """Custom validation to match Go struct validation logic."""
        # Validate that excludeAccounts and featureNames are set together
        if (self.excludeAccounts is None) != (len(self.featureNames) == 0):
            raise ValueError("excludeAccounts and featureNames must be set together")
        return super().model_validate(data)


class SyncCloudOrganizationRequest(BaseModel):
    """Request model for syncing cloud organization."""
    orgGUID: str
    skipScan: bool = False