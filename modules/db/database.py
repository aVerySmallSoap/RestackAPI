from math import floor

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import database_exists, create_database
import uuid

from modules.db.session import Base
from modules.db.table_collection import Report, TechDiscovery, Scan


class Database:

    _engine = None
    _url = "postgresql+psycopg2://postgres:root@localhost:5432/restack"

    def __int__(self):
        pass

    def _check_engine(self):
        """Check if the database exists, if not, create it"""
        if not database_exists(self._url):
            create_database(self._url)
            self._engine = create_engine(self._url)
            return self._engine
        else:
            self._engine = create_engine(self._url)
            return self._engine

    def clean(self):
        engine = self._check_engine()
        Base.metadata.drop_all(engine)

    def migrate(self):
        engine = self._check_engine()
        Base.metadata.create_all(engine)

    def insert_wapiti_quick_report(self, timestamp, file_path:str, data, duration: float):
        engine = self._check_engine()
        _tables = []
        with Session(engine) as session:
            report_id = str(uuid.uuid4())
            report = Report(
                id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scan_type="Quick Scan",
                scanner="Wapiti",
                path=file_path
            )
            tech_disc = TechDiscovery(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                data=data
            )
            _tables.append(report)
            scan = Scan(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="Wapiti",
                scan_type="Quick Scan",
                data=data,
                scan_duration=floor(duration),
                target_url=file_path
            )
            _tables.append(tech_disc)
            _tables.append(scan)
            session.add_all(_tables)
            session.commit()

    @property
    def engine(self):
        if self._engine is None:
            self._engine = self._check_engine()
        return self._engine