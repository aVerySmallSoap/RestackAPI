from datetime import datetime
from sqlalchemy import String, ForeignKey, Column, JSON
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy.testing.schema import mapped_column

from modules.db.session import Base

class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(primary_key=True)
    scan_date: Mapped[datetime]
    scanner: Mapped[str] = mapped_column(String(50))
    scan_type: Mapped[str] = mapped_column(String(50))
    path: Mapped[str]
    total_vulnerabilities: Mapped[int]
    critical_count: Mapped[int]
    scan = relationship("Scan", back_populates="parent", cascade="all, delete-orphan", passive_deletes=True)
    tech = relationship("TechDiscovery", back_populates="parent", cascade="all, delete-orphan", passive_deletes=True)

class TechDiscovery(Base):
    __tablename__ = "tech_discovery"

    id: Mapped[str] = mapped_column(primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey("reports.id"))
    scan_date: Mapped[datetime] = mapped_column(String(50))
    data = Column(JSON)
    parent = relationship("Report", back_populates="tech")

class Scan(Base):
    __tablename__ = "scan"

    id: Mapped[str] = mapped_column(primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey('reports.id'))
    scan_date: Mapped[datetime]
    scanner: Mapped[str] = mapped_column(String(50))
    scan_type: Mapped[str] = mapped_column(String(50))
    scan_duration: Mapped[float]
    crawl_depth: Mapped[int]
    target_url: Mapped[str]
    data = Column(JSON)
    parent = relationship("Report", back_populates="scan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey('reports.id'))
    scan_date: Mapped[datetime]
    scanner: Mapped[str] = mapped_column(String(50))
    vulnerability_type: Mapped[str] = mapped_column(String(100))
    severity:Mapped[str] = mapped_column(String(50))
    info:Mapped[str]
    endpoint: Mapped[str]
    remediation_effort: Mapped[str]
    http_method: Mapped[str]
    parameters = Mapped[str]
    data = Column(JSON)
