from pydantic import BaseModel, Field
from typing import Literal
from enum import Enum


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# RPM: Required Permissions Manifest 

class SDKCall(BaseModel):
    service: str                          # e.g. "s3"
    action: str                           # e.g. "GetObject"
    action_iam: str                       # e.g. "s3:GetObject" (always fully qualified)
    resources: list[str] = Field(default_factory=list)
    resources_wildcard: bool = False
    confidence: Confidence


class RPM(BaseModel):
    service_name: str
    language: Literal["python", "typescript", "go", "java"]
    commit_sha: str
    sdk_calls: list[SDKCall]


#  GPM: Granted Permissions Manifest

class Statement(BaseModel):
    effect: Literal["Allow", "Deny"]
    actions: list[str]              # raw, as written (may include wildcards like "s3:*")
    actions_expanded: list[str]     # wildcards always expanded to explicit actions here
    actions_wildcard: bool
    resources: list[str]
    resources_wildcard: bool


class AttachedPolicy(BaseModel):
    policy_arn: str
    statements: list[Statement]


class GPM(BaseModel):
    role_name: str
    role_arn: str
    created_by: str | None = None
    last_modified_pr: str | None = None
    attached_policies: list[AttachedPolicy]


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class OverPrivilegeType(str, Enum):
    ACTION = "action"
    RESOURCE = "resource"

class MatchMethod(str, Enum):
    FUZZY_NAME = "fuzzy_name"
    MANIFEST = "manifest"
    AMBIGUOUS = "ambiguous"

class DeltaEntry(BaseModel):
    action_iam: str
    over_privilege_type: OverPrivilegeType
    severity: Severity
    confidence: Confidence
    reason: str

class DeltaResult(BaseModel):
    role_arn: str
    role_name: str
    commit_sha: str
    matched_by: MatchMethod
    rpm_service_name: str
    excess: list[DeltaEntry]
    requires_human_review: bool
    patch_risk: Literal["green", "yellow", "red"]   