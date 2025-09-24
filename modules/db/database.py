import datetime
from math import floor

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import database_exists, create_database
import uuid

from modules.db.session import Base
from modules.db.table_collection import Report, TechDiscovery, Scan, Vulnerability


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

    def insert_wapiti_quick_report(self, timestamp:datetime, file_path:str, plugins: list, raw_data: dict, duration: float):
        engine = self._check_engine()
        _tables = []
        with Session(engine) as session:
            # TODO: raw_data access is now in SARIF
            report_id = str(uuid.uuid4())
            report = Report(
                id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scan_type="Quick Scan",
                scanner="Wapiti",
                path=file_path,
                total_vulnerabilities=raw_data["vulnerability_count"],
                critical_count=raw_data["critical_vulnerabilities"]
            )
            tech_disc = TechDiscovery(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                data=plugins
            )
            _tables.append(report)
            scan = Scan(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="Wapiti",
                scan_type="Quick Scan",
                data=raw_data["parsed"],
                crawl_depth=raw_data["extra"]["crawled_pages_nbr"],
                scan_duration=floor(duration),
                target_url=raw_data["extra"]["target"]
            )
            _tables.append(tech_disc)
            _tables.append(scan)
            session.add_all(_tables)
            self._insert_wapiti_vulnerabilities(report_id, timestamp, raw_data, session)
            session.commit()

    def insert_zap_report(self, timestamp: datetime, file_path: str, plugins:list, raw_data: dict, duration: float):
        engine = self._check_engine()
        _tables = []
        with Session(engine) as session:
            # TODO: raw_data access is now in SARIF, need to change how it is accessed
            report_id = str(uuid.uuid4())
            report = Report(
                id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scan_type="Zap Scan",
                scanner="Zap",
                path=file_path,
                total_vulnerabilities=raw_data["vulnerability_count"],
                critical_count=raw_data["critical_vulnerabilities"]
            )
            _tables.append(report)
            tech_disc = TechDiscovery(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                data=plugins
            )
            scan = Scan(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="Zap",
                scan_type="Zap Scan",
                data=raw_data["parsed"],
                crawl_depth=raw_data["crawled_pages"],
                scan_duration=floor(duration),
                target_url=raw_data["parsed"][0]["url"]
            )
            _tables.append(tech_disc)
            _tables.append(scan)
            session.add_all(_tables)
            self._insert_zap_vulnerabilities(report_id, timestamp, raw_data["parsed"], session)
            session.commit()

    @staticmethod
    def _insert_zap_vulnerabilities(parent_report_id: str, scan_time:datetime, raw_data: dict, session: Session):
        _entries = []
        for vulnerability in raw_data:
            _vuln = Vulnerability(
                id=str(uuid.uuid4()),
                report_id=parent_report_id,
                scan_date=scan_time.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="Zap",
                vulnerability_type=vulnerability["name"],
                severity=vulnerability["risk"],
                info=vulnerability["description"], #TODO: there should be a unified thing here (no info in zap unlike wapiti, or at least its counter-part)
                endpoint=vulnerability["endpoint"],
                remediation_effort=vulnerability["solution"],
                method=vulnerability["method"],
                confidence=vulnerability["confidence"],
                params=vulnerability["param"],
                data=vulnerability
            )
            _entries.append(_vuln)
        session.add_all(_entries)


    @staticmethod
    def _insert_wapiti_vulnerabilities(parent_report_id: str, scan_time:datetime, data:dict, session: Session):
        raw_data = data["raw"]
        parsed_data = data["parsed"] #TODO: Cleanup and use a template
        _entries = []
        for category in parsed_data["categories"]:
            for vulnerability in raw_data["vulnerabilities"][category]:
                _vuln = Vulnerability(
                    id=str(uuid.uuid4()),
                    report_id=parent_report_id,
                    scan_date=scan_time.strftime("%Y-%m-%d %H:%M:%S"),
                    scanner="Wapiti",
                    vulnerability_type=category,
                    severity=vulnerability["level"],
                    info=vulnerability["info"],
                    endpoint=vulnerability["path"],
                    remediation_effort=raw_data["classifications"][category]["sol"],
                    method=vulnerability["method"],
                    params= vulnerability["parameter"],
                    confidence="Low", #TODO: find something to replace this constant
                    data=vulnerability,
                )
                _entries.append(_vuln)
        session.add_all(_entries)

    @property
    def engine(self):
        if self._engine is None:
            self._engine = self._check_engine()
        return self._engine