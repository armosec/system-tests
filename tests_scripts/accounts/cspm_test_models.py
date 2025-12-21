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
    "cis_2.1": -1,
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
    "resource_id" : "arn:aws:ec2:eu-west-1:686255980207:instance/i-0df4d10d2f2ae99f7",
    "failed_controls_count": 1,
    "passed_controls_count": 1,
    "high_severity_controls": 0
}

DEFAULT_TEST_CONFIG_AZURE = {
    "framework": "cis_3.0",
    "control_name": "Ensure That 'Notify about alerts with the following severity' is Set to 'High'",
    "rule_name": "Ensure That 'Notify about alerts with the following severity' is Set to 'High'",
    "rule_hash": "a8ec28b1-8c97-4b7b-ab82-db3b5d3ccdaa",
    "rule_id": "defender_ensure_notify_alerts_severity_is_high",
    "check_type": "AUTOMATED",
    "severity": "high",
    "status": "FAIL",
    "resource_hash": "bb1c4e9a-e7e5-36ad-d0d8-bc936f6149b6",
    "resource_name": "default",
    "resource_type": "defender",
    "resource_id": "/subscriptions/57e3175c-71ce-45f8-8bfc-34d966223068/providers/Microsoft.Security/securityContacts/default",
    "failed_controls_count": 3,
    "passed_controls_count": 0,
    "high_severity_controls": 1
}

TEST_CONFIG_PROVIDER_MAP = {
    PROVIDER_AWS: DEFAULT_TEST_CONFIG_AWS,
    PROVIDER_AZURE: DEFAULT_TEST_CONFIG_AZURE,
    # PROVIDER_GCP: DEFAULT_TEST_CONFIG_GCP,
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

    containsAcceptedControlCount : int
    tickets: Optional[List[Dict]] = None

def get_expected_control_response(provider: str, with_accepted_resources: bool = False) -> Dict:
    """Get expected response for control API (AWS-specific)."""
    default_test_config = TEST_CONFIG_PROVIDER_MAP[provider]
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "frameworkName": default_test_config["framework"],
        "section": "",  # This will be checked to be non-empty
        "cloudControlName": default_test_config["control_name"],
        "status": "ACCEPT" if with_accepted_resources else default_test_config["status"],
        "severity":"none" if with_accepted_resources else default_test_config["severity"],
        "checkType": default_test_config["check_type"],
        "affectedResourcesCount": 1,
        "failedResourcesCount": 0 if with_accepted_resources else 1,
        "totalScannedResourcesCount": 1,
        "acceptedResourcesCount": 1 if with_accepted_resources else 0,
        "complianceScore": 100.0 if with_accepted_resources else 0.0,
        "exceptionApplied": True if with_accepted_resources else False
    }

def get_expected_rules_response(provider: str, with_accepted_resources: bool = False) -> Dict:
    """Get expected response for check API (AWS-specific)."""
    default_test_config = TEST_CONFIG_PROVIDER_MAP[provider]
    return {
        "cloudCheckName": default_test_config["rule_name"],
        "cloudCheckHash": default_test_config["rule_hash"],
        "cloudCheckID": default_test_config["rule_id"],
        "status": "ACCEPT" if with_accepted_resources else default_test_config["status"],
        "severity": "none" if with_accepted_resources else default_test_config["severity"],
        "checkType": default_test_config["check_type"],
        "totalScannedResourcesCount": 1,
        "failedResourcesCount": 0 if with_accepted_resources else 1,
        "acceptedResourcesCount": 1 if with_accepted_resources else 0,
        "exceptionApplied": True if with_accepted_resources else False
    }

def get_expected_resources_under_check_response(provider: str, with_accepted_resources: bool = False) -> Dict:
    """Get expected response for resource-to-check API (AWS-specific)."""
    default_test_config = TEST_CONFIG_PROVIDER_MAP[provider]
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "cloudResourceHash": default_test_config["resource_hash"],
        "cloudResourceName": default_test_config["resource_name"],
        "cloudResourceID": default_test_config["resource_id"],
        "cloudResourceType": default_test_config["resource_type"],
        "exceptionApplied": True if with_accepted_resources else False
    }

def get_expected_resource_summaries_response(provider: str, with_accepted_resources: bool = False) -> Dict:
    """Get expected response for resource-summaries API (AWS-specific)."""
    default_test_config = TEST_CONFIG_PROVIDER_MAP[provider]
    failed_controls_count = default_test_config["failed_controls_count"]
    high_severity_controls = default_test_config["high_severity_controls"]
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "cloudAccountGUID": "",  # This will be compared separately
        "provider": provider,
        "cloudResourceName": default_test_config["resource_name"],
        "cloudResourceID": default_test_config["resource_id"],
        "cloudResourceHash": default_test_config["resource_hash"],
        "cloudResourceType": default_test_config["resource_type"],
        "frameworkName": default_test_config["framework"],
        "failedControlsCount": max(0, failed_controls_count - 1) if with_accepted_resources else failed_controls_count,
        "passedControlsCount": default_test_config["passed_controls_count"],
        "manualControlsCount": 0,
        "containsAcceptedControlCount": 1 if with_accepted_resources else 0,
        "criticalSeverityControls": 0,
        "highSeverityControls": max(0, high_severity_controls - 1) if with_accepted_resources else high_severity_controls,
        "mediumSeverityControls": "", # Placeholder value (not validated, only key is checked)
        "lowSeverityControls": 0,
    }

def get_expected_only_check_under_control_response(provider: str, with_accepted_resources: bool = False) -> Dict:
    """Get expected response for control-with-checks API (AWS-specific)."""
    default_test_config = TEST_CONFIG_PROVIDER_MAP[provider]
    return {
        "reportGUID": "",  # This will be compared separately with the actual scan ID
        "exceptionApplied": True if with_accepted_resources else False,
        "severity": default_test_config["severity"],
        "status": default_test_config["status"],
        "checkType": default_test_config["check_type"],
        "cloudCheckHash": default_test_config["rule_hash"],
        "cloudCheckID": default_test_config["rule_id"],
        "cloudCheckName": default_test_config["rule_name"],
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