from __future__ import annotations
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RunInfo(BaseModel):
    id: str
    repo: str
    branch: Optional[str] = None
    commit: Optional[str] = None
    started_at: Optional[str] = None  # ISO8601
    completed_at: Optional[str] = None  # ISO8601


class MappingInfo(BaseModel):
    repos: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    skip_cluster: bool = False


class Identifiers(BaseModel):
    customer_guid: Optional[str] = None
    cluster: Optional[str] = None
    test_run_id: Optional[str] = None  # Extracted from "Test Run ID:" in logs
    extra: Dict[str, Any] = Field(default_factory=dict)


class LokiData(BaseModel):
    queries: List[str] = Field(default_factory=list)
    excerpts: List[str] = Field(default_factory=list)
    from_time: Optional[str] = None  # ISO8601
    to_time: Optional[str] = None    # ISO8601


class FailureEntry(BaseModel):
    test: Dict[str, Any]  # {name, file, suite, ...} - keep flexible
    mapping: MappingInfo = Field(default_factory=MappingInfo)
    identifiers: Identifiers = Field(default_factory=Identifiers)
    loki: LokiData = Field(default_factory=LokiData)
    category: Optional[str] = None  # infra|service|flake
    confidence: Optional[float] = None
    notes: Optional[str] = None
    time_start: Optional[str] = None  # ISO8601 from Step 18 first log
    time_end: Optional[str] = None    # ISO8601 from Step 18 last log
    errors: List[str] = Field(default_factory=list)
    incluster_logs: Dict[str, List[Dict[str, Any]]] = Field(default_factory=dict)  # component -> log entries


class Report(BaseModel):
    run: RunInfo
    failures: List[FailureEntry] = Field(default_factory=list)
    summary: Optional[str] = None


