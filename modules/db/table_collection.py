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
    # children = relationship("Scan", back_populates="report", uselist=False)

class Scan(Base):
    __tablename__ = "scan"

    id: Mapped[str] = mapped_column(primary_key=True)
    report_id: Mapped[str] = mapped_column(ForeignKey('reports.id'))
    scan_date: Mapped[datetime]
    scanner: Mapped[str] = mapped_column(String(50))
    scan_type: Mapped[str] = mapped_column(String(50))
    data = Column(JSON)
    # parent = relationship("Report", back_populates="scan")
