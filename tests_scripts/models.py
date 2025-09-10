from pydantic import BaseModel
from typing import List, Union


class SyncCloudOrganizationRequest(BaseModel):
    """Request model for syncing cloud organization."""
    orgGUID: str
    withoutScan: bool = False
