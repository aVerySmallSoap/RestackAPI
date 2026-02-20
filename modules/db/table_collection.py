from datetime import datetime
from typing import Optional

from sqlalchemy import String, ForeignKey, JSON, Text, Boolean
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy.testing.schema import mapped_column
from sqlalchemy import BigInteger

from modules.db.session import Base


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(primary_key=True)
    scan_date: Mapped[datetime]
    scanner: Mapped[str] = mapped_column(String(50))
    scan_type: Mapped[str] = mapped_column(String(50))
    total_vulnerabilities: Mapped[int]
    critical_count: Mapped[int]

    # Analytics Data (from Laravel migration 2026_02_05_001029)
    ai_summary_vulnerabilities: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_summary_tech: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Priority Matrix Quadrants
    high_severity_high_confidence: Mapped[int] = mapped_column(default=0)
    high_severity_low_confidence: Mapped[int] = mapped_column(default=0)
    low_severity_high_confidence: Mapped[int] = mapped_column(default=0)
    low_severity_low_confidence: Mapped[int] = mapped_column(default=0)

    # Summary Statistics
    scanner_agreement_rate: Mapped[Optional[float]] = mapped_column(nullable=True)
    confidence_rate: Mapped[Optional[float]] = mapped_column(nullable=True)
    high_confidence_vulns: Mapped[int] = mapped_column(default=0)
    medium_confidence_vulns: Mapped[int] = mapped_column(default=0)
    low_confidence_vulns: Mapped[int] = mapped_column(default=0)

    # Timestamps (Laravel default)
    created_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)

    scan = relationship("Scan", back_populates="parent", cascade="all, delete-orphan", passive_deletes=True)
    tech = relationship("TechDiscovery", back_populates="parent", cascade="all, delete-orphan", passive_deletes=True)


class TechDiscovery(Base):
    __tablename__ = "tech_discovery"

    id: Mapped[str] = mapped_column(primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id"))
    scan_date: Mapped[datetime] = mapped_column(String(50))
    data: Mapped[JSON] = mapped_column(JSON())
    
    # Timestamps (Laravel default)
    created_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    
    parent = relationship("Report", back_populates="tech")


class Scan(Base):
    __tablename__ = "scan"

    id: Mapped[str] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)  # from 2025_12_05_041252
    is_automated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)  # from 2026_02_06_145448
    report_id: Mapped[str] = mapped_column(ForeignKey('reports.id'))
    scan_date: Mapped[datetime]
    scanner: Mapped[str] = mapped_column(String(50))
    scan_type: Mapped[str] = mapped_column(String(50))
    scan_duration: Mapped[float]
    crawl_depth: Mapped[int]
    target_url: Mapped[str]
    data: Mapped[JSON] = mapped_column(JSON())
    
    # Timestamps (from 2025_12_05_042756)
    created_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    
    parent = relationship("Report", back_populates="scan")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey('reports.id'))
    scan_date: Mapped[datetime]
    scanner: Mapped[str] = mapped_column(String(50))
    vulnerability_type: Mapped[str] = mapped_column(String(100))
    severity: Mapped[str] = mapped_column(String(50))
    confidence: Mapped[str] = mapped_column(String(25))
    http_request: Mapped[Optional[JSON]] = mapped_column(JSON(), nullable=True)
    description: Mapped[str] = mapped_column(Text)
    endpoint: Mapped[str]
    remediation_effort: Mapped[str] = mapped_column(Text)
    method: Mapped[str]
    state: Mapped[str]
    data: Mapped[JSON] = mapped_column(JSON())
    
    # Timestamps (Laravel default)
    created_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)


class ScheduledScans(Base):
    __tablename__ = "scheduled_scans"

    id: Mapped[str] = mapped_column(primary_key=True)
    user_id: Mapped[Optional[int]] = mapped_column(BigInteger, nullable=True)  # from 2026_02_03_080052
    url: Mapped[str] = mapped_column(String())
    codename: Mapped[str] = mapped_column(String(), unique=True)
    job_type: Mapped[str] = mapped_column(String())
    configuration: Mapped[JSON] = mapped_column(JSON())
    
    # Timestamps (from 2026_02_03_080052)
    created_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)


class ActiveScan(Base):
    """
    Temporary table to track running scans across multiple Uvicorn workers.
    Replaces active_scans.json
    """
    __tablename__ = "active_scans"

    session_id: Mapped[str] = mapped_column(String, primary_key=True)
    target: Mapped[str] = mapped_column(String)
    step: Mapped[str] = mapped_column(String)
    start_time: Mapped[str] = mapped_column(String)