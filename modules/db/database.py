from sqlalchemy import create_engine
from sqlalchemy.orm import Session, DeclarativeBase
from sqlalchemy_utils import database_exists, create_database
import uuid

from modules.db.tables.Reports import Report

class Base(DeclarativeBase):
    pass

class Database:

    _engine = None
    _url = "postgresql+psycopg2://postgres:root@localhost:5432/restack"
    _Base = DeclarativeBase()

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

    def migrate(self):
        engine = self._check_engine()
        Base.metadata.create_all(engine)

    def insert_wapiti_report(self, timestamp, url):
        engine = self._check_engine()
        with Session(engine) as session:
            report = Report(
                id=str(uuid.uuid4()),
                scan_date=timestamp,
                scan_type="Quick Scan",
                scanner="Wapiti",
                path=url
            )
            session.add(report)
            session.commit()

    @property
    def engine(self):
        if self._engine is None:
            self._engine = self._check_engine()
        return self._engine
