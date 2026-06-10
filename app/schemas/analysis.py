from pydantic import BaseModel, Field
from typing import Optional, Dict, List, Any
from datetime import datetime
from app.db.models import JobStatus


class JobCreateResponse(BaseModel):
    job_id: str
    status: JobStatus
    message: str


class CertificateInfo(BaseModel):
    subject: Optional[str]
    issuer: Optional[str]
    serial: Optional[str]
    not_before: Optional[str]
    not_after: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]
    is_self_signed: Optional[bool]


class HardcodedIOCs(BaseModel):
    urls: List[str] = []
    ips: List[str] = []
    emails: List[str] = []
    crypto_keys: List[str] = []
    base64_blobs: List[str] = []
    package_refs: List[str] = []
    file_paths: List[str] = []
    phone_numbers: List[str] = []


class RiskFlag(BaseModel):
    flag: str
    severity: str    # critical / high / medium / low
    detail: str


class AnalysisResult(BaseModel):
    job_id: str
    filename: str
    file_size: Optional[int]
    status: JobStatus
    created_at: datetime
    updated_at: datetime
    error_message: Optional[str] = None
    progress_percent: Optional[int] = 0
    progress_label: Optional[str] = None

    # hashes
    md5: Optional[str] = None
    sha1: Optional[str] = None
    sha256: Optional[str] = None

    # manifest
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[int] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None

    # components
    permissions: Optional[List[str]] = None
    activities: Optional[List[str]] = None
    services: Optional[List[str]] = None
    receivers: Optional[List[str]] = None
    providers: Optional[List[str]] = None
    intent_filters: Optional[List[str]] = None

    # extraction
    strings: Optional[Dict[str, List[str]]] = None
    hardcoded: Optional[HardcodedIOCs] = None
    api_calls: Optional[List[str]] = None
    native_libs: Optional[List[str]] = None
    classes_count: Optional[int] = None
    methods_count: Optional[int] = None

    # certificate
    certificate: Optional[CertificateInfo] = None

    # risk
    risk_score: Optional[float] = None
    risk_flags: Optional[List[dict]] = None

    # artifact download path
    zip_artifact_available: bool = False

    class Config:
        from_attributes = True


class HashLookupResult(BaseModel):
    hash_value: str
    hash_type: str           # md5 / sha1 / sha256
    source: str              # virustotal / local_db
    found: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class JobListItem(BaseModel):
    job_id: str
    filename: str
    status: JobStatus
    package_name: Optional[str]
    risk_score: Optional[float]
    sha256: Optional[str]
    progress_percent: Optional[int] = 0
    progress_label: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
