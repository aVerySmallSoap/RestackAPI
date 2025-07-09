from datetime import datetime
from sqlalchemy import String, JSON
from sqlalchemy.orm import Mapped
from sqlalchemy.testing.schema import mapped_column

from modules.db.session import Base

class Scans(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(primary_key=True)
    scan_date: Mapped[datetime]
    scanner: Mapped[str] = mapped_column(String(50))
    scan_type: Mapped[str] = mapped_column(String(50))
    data: Mapped[JSON]