from sqlalchemy import Column, String, Integer, Float, Text, DateTime, JSON, Enum as SAEnum
from sqlalchemy.orm import DeclarativeBase
from datetime import datetime, timezone
import enum


class Base(DeclarativeBase):
    pass


class JobStatus(str, enum.Enum):
    pending   = "pending"
    running   = "running"
    completed = "completed"
    failed    = "failed"


class AnalysisJob(Base):
    __tablename__ = "analysis_jobs"

    id             = Column(String, primary_key=True)
    filename       = Column(String, nullable=False)
    file_size      = Column(Integer)
    status         = Column(SAEnum(JobStatus), default=JobStatus.pending, nullable=False)
    created_at     = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at     = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                            onupdate=lambda: datetime.now(timezone.utc))
    error_message  = Column(Text, nullable=True)
    progress_percent = Column(Integer, default=0, nullable=False)
    progress_label   = Column(String, default="Queued for analysis", nullable=True)

    # hashes
    md5            = Column(String(32),  nullable=True)
    sha1           = Column(String(40),  nullable=True)
    sha256         = Column(String(64),  nullable=True)

    # manifest basics
    package_name   = Column(String,   nullable=True)
    version_name   = Column(String,   nullable=True)
    version_code   = Column(Integer,  nullable=True)
    min_sdk        = Column(Integer,  nullable=True)
    target_sdk     = Column(Integer,  nullable=True)

    # JSON blobs
    permissions    = Column(JSON, nullable=True)   # list[str]
    activities     = Column(JSON, nullable=True)   # list[str]
    services       = Column(JSON, nullable=True)
    receivers      = Column(JSON, nullable=True)
    providers      = Column(JSON, nullable=True)
    intent_filters = Column(JSON, nullable=True)

    # static extraction results
    strings        = Column(JSON, nullable=True)   # {category: [str]}
    hardcoded      = Column(JSON, nullable=True)   # {urls, ips, emails, keys, ...}
    api_calls      = Column(JSON, nullable=True)   # list of interesting API calls
    native_libs    = Column(JSON, nullable=True)   # list[str]
    classes_count  = Column(Integer, nullable=True)
    methods_count  = Column(Integer, nullable=True)

    # certificate / signature
    cert_subject   = Column(Text, nullable=True)
    cert_issuer    = Column(Text, nullable=True)
    cert_serial    = Column(String, nullable=True)
    cert_not_before = Column(String, nullable=True)
    cert_not_after  = Column(String, nullable=True)
    cert_sha1       = Column(String(40), nullable=True)
    cert_sha256     = Column(String(64), nullable=True)
    is_self_signed  = Column(Integer, nullable=True)   # 0/1

    # risk scoring
    risk_score     = Column(Float, nullable=True)      # 0.0 – 10.0
    risk_flags     = Column(JSON,  nullable=True)      # list of flag strings

    # artifact paths
    zip_artifact   = Column(String, nullable=True)     # path to decompiled zip
