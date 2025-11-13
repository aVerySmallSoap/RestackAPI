import datetime
import json
from math import floor

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import database_exists, create_database
import uuid
import modules.utils.__utils__ as utils

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

    def insert_wapiti_quick_report(self, timestamp: datetime, file_path:str, plugins: list, raw_data: dict, duration: float):
        engine = self._check_engine()
        _tables = []
        with Session(engine) as session:
            report_id = str(uuid.uuid4())
            report = Report(
                id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scan_type="wapiti scan",
                scanner="wapiti",
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
                scanner="wapiti",
                scan_type="wapiti scan",
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

    def insert_zap_report(self, timestamp: datetime, file_path: str, plugins:list, raw_data: dict, duration: float, url):
        engine = self._check_engine()
        _tables = []
        _data_dump = json.dumps(raw_data)
        _plugins_dump = json.dumps(plugins)
        with Session(engine) as session:
            report_id = str(uuid.uuid4())
            report = Report(
                id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scan_type="zap scan",
                scanner="zap",
                path=file_path,
                total_vulnerabilities=len(raw_data["runs"][0]["results"]),
                critical_count=utils.critical_counter(raw_data)
            )
            _tables.append(report)
            tech_disc = TechDiscovery(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                data=_plugins_dump
            )
            scan = Scan(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="zap",
                scan_type="zap scan",
                data=_data_dump,
                crawl_depth=0, #TODO: fetch crawler results and add data here
                scan_duration=floor(duration),
                target_url=url
            )
            _tables.append(tech_disc)
            _tables.append(scan)
            session.add_all(_tables)
            self._insert_zap_vulnerabilities(report_id, timestamp, raw_data, session)
            session.commit()

    def insert_scan_report(self, timestamp: datetime, file_path: str, plugins:list, \
                           zap_raw_data: dict, wapiti_raw_data: dict, analytics_data: dict, duration: float, url):
        engine = self._check_engine()
        _tables = []
        _zap_dump = json.dumps(zap_raw_data)
        _wapiti_dump = json.dumps(wapiti_raw_data)
        _plugins_dump = json.dumps(plugins)
        with Session(engine) as session:
            report_id = str(uuid.uuid4())
            report = Report(
                id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scan_type="full scan",
                scanner="all",
                path=file_path,
                total_vulnerabilities=len(analytics_data["union"]),
                critical_count=utils.critical_counter(analytics_data["union"], analytics_data["rules"]),
            )
            _tables.append(report)
            tech_disc = TechDiscovery(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                data=_plugins_dump
            ) # Search_vulns table??
            scan = Scan(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="all",
                scan_type="full scan",
                data=analytics_data["union"],
                crawl_depth=0,  # TODO: fetch crawler results and add data here
                scan_duration=floor(duration),
                target_url=url
            )
            _tables.append(tech_disc)
            _tables.append(scan)
            session.add_all(_tables)
            self._insert_zap_vulnerabilities(report_id, timestamp, zap_raw_data, session)
            self._insert_wapiti_vulnerabilities(report_id, timestamp, wapiti_raw_data, session)
            session.commit()

    @staticmethod
    def _insert_zap_vulnerabilities(parent_report_id: str, scan_time: datetime, raw_data: dict, session: Session):
        _entries = []
        _rules = utils.unroll_sarif_rules(raw_data)
        for vulnerability in raw_data["runs"][0]["results"]:
            _rule = _rules.get(vulnerability["ruleId"])
            _json_dump = json.dumps(vulnerability)
            _vuln = Vulnerability(
                id=str(uuid.uuid4()),
                report_id=parent_report_id,
                scan_date=scan_time.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="zap",
                vulnerability_type=_rule["name"],
                severity=_rule["properties"]["risk"],
                description=_rule["fullDescription"]["text"],
                http_request= json.dumps(vulnerability["properties"]["har"]) if vulnerability["properties"]["har"] is not None else None,
                endpoint=vulnerability["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                remediation_effort=_rule["help"]["text"],
                method=vulnerability["properties"]["method"],
                confidence=vulnerability["properties"]["confidence"],
                state="new",
                data=_json_dump
            )
            _entries.append(_vuln)
        session.add_all(_entries)


    @staticmethod
    def _insert_wapiti_vulnerabilities(parent_report_id: str, scan_time: datetime, raw_data:dict, session: Session):
        _entries = []
        _rules = utils.unroll_sarif_rules(raw_data)
        for vulnerability in raw_data["runs"][0]["results"]:
            _rule = _rules.get(vulnerability["ruleId"])
            _json_dump = json.dumps(vulnerability)
            _severity = vulnerability["level"]
            if str.lower(_severity) == "note":
                _severity = "Low"
            elif str.lower(_severity) == "warning":
                _severity = "Medium"
            elif str.lower(_severity) == "error":
                _severity = "High"
            else:
                _severity = "none"
            _vuln = Vulnerability(
                id=str(uuid.uuid4()),
                report_id=parent_report_id,
                scan_date=scan_time.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="wapiti",
                vulnerability_type=_rule["shortDescription"]["text"],
                severity= _severity,
                http_request=vulnerability["properties"]["http_request"],
                endpoint=vulnerability["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                remediation_effort=_rule["help"]["text"],
                method=vulnerability["properties"]["method"],
                state="new",
                confidence="Low",
                data=_json_dump
            )
            _entries.append(_vuln)
        session.add_all(_entries)

    @property
    def engine(self):
        if self._engine is None:
            self._engine = self._check_engine()
        return self._engine

    def get_report_by_id(self, report_id: str):
        engine = self._check_engine()
        with Session(engine) as session:
            report = session.query(Report).filter(Report.id == report_id).first()
            if not report:
                return None
            # Assume SARIF is stored in the path attribute as a file path
            result = {
                'id': report.id,
                'scan_date': report.scan_date,
                'scan_type': report.scan_type,
                'scanner': report.scanner.upper() if report.scanner else None,
                'raw_data': report.path  # path to SARIF file
            }
            return result
