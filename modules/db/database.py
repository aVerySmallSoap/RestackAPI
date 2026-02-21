import datetime
import json
import uuid
from math import floor

from loguru import logger
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy_utils import create_database, database_exists
from typing_extensions import deprecated

import modules.utils.__utils__ as utils
from modules.analytics.analytics_helper import compute_and_attach_analytics
from modules.db.session import Base
from modules.db.table_collection import Report, Scan, TechDiscovery, Vulnerability
from modules.utils.load_configs import DEV_ENV


class Database:
    _engine = None
    _url = DEV_ENV["api_keys"]["database"]

    def __int__(self):
        pass

    def _check_engine(self):
        """Check if the database exists, if not, create it then load it, else, load it"""
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

    def insert_wapiti_quick_report(
        self,
        timestamp: datetime,
        plugins: list,
        raw_data: dict,
        duration: float,
        url: str = "N/A",
        user_id: int = None,
        is_automated=False,
        report_id=None,
    ):
        engine = self._check_engine()
        _tables = []
        with Session(engine) as session:
            if report_id is None:
                report_id = str(uuid.uuid4())
            report = Report(
                id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scan_type="wapiti scan",
                scanner="wapiti",
                total_vulnerabilities=len(raw_data["runs"][0]["results"]),
                critical_count=utils.critical_counter(raw_data),
            )
            tech_disc = TechDiscovery(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                data=plugins,
            )
            _tables.append(report)
            scan = Scan(
                id=str(uuid.uuid4()),
                report_id=report_id,
                user_id=user_id,
                is_automated=is_automated,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="wapiti",
                scan_type="wapiti scan",
                data=raw_data,
                crawl_depth=0,
                scan_duration=floor(duration),
                target_url=url,
            )
            _tables.append(tech_disc)
            _tables.append(scan)
            session.add_all(_tables)
            self._insert_wapiti_vulnerabilities(report_id, timestamp, raw_data, session)
            session.commit()
            return report_id

    def insert_zap_report(
        self,
        timestamp: datetime,
        plugins: list,
        raw_data: dict,
        duration: float,
        url,
        user_id: int = None,
    ):
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
                total_vulnerabilities=len(raw_data["runs"][0]["results"]),
                critical_count=utils.critical_counter(raw_data),
            )
            _tables.append(report)
            tech_disc = TechDiscovery(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                data=_plugins_dump,
            )
            scan = Scan(
                id=str(uuid.uuid4()),
                report_id=report_id,
                user_id=user_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="zap",
                scan_type="zap scan",
                data=_data_dump,
                crawl_depth=0,
                scan_duration=floor(duration),
                target_url=url,
            )
            _tables.append(tech_disc)
            _tables.append(scan)
            session.add_all(_tables)
            self._insert_zap_vulnerabilities(report_id, timestamp, raw_data, session)
            session.commit()
            return report_id

    def insert_scan_report(
        self,
        timestamp: datetime,
        plugins: list,
        zap_raw_data: dict,
        wapiti_raw_data: dict,
        nuclei_raw_data: dict,
        analytics_data: dict,
        duration: float,
        url,
        user_id: int = None,
        summary_stats: dict = None,
        priority_matrix: dict = None,
        ai_summary: dict = None,
        is_automated=False,
        report_id=None,
    ):
        engine = self._check_engine()
        _tables = []
        _zap_dump = json.dumps(zap_raw_data)
        _wapiti_dump = json.dumps(wapiti_raw_data)
        _plugins_dump = json.dumps(plugins)
        total_union = sum(
            len(scanner_results) for scanner_results in analytics_data["union"]
        )
        total_intersection = len(analytics_data.get("intersection", []))
        total_vulnerabilities = total_union + total_intersection
        with Session(engine) as session:
            if report_id is None:
                report_id = str(uuid.uuid4())
            report = Report(
                id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scan_type="full scan",
                scanner="all",
                total_vulnerabilities=total_vulnerabilities,
                critical_count=utils.critical_counter(
                    analytics_data["union"], analytics_data["rules"]
                ),
            )

            # ATTACH PRE-COMPUTED ANALYTICS
            if summary_stats:
                report.high_confidence_vulns = summary_stats.get(
                    "high_confidence_vulns", 0
                )
                report.medium_confidence_vulns = summary_stats.get(
                    "medium_confidence_vulns", 0
                )
                report.low_confidence_vulns = summary_stats.get(
                    "low_confidence_vulns", 0
                )

                agreement_str = summary_stats.get("scanner_agreement_rate", "0%")
                confidence_str = summary_stats.get("confidence_rate", "0%")

                report.scanner_agreement_rate = (
                    float(agreement_str.rstrip("%")) if agreement_str else 0.0
                )
                report.confidence_rate = (
                    float(confidence_str.rstrip("%")) if confidence_str else 0.0
                )

            if priority_matrix:
                report.high_severity_high_confidence = priority_matrix[
                    "quadrant_counts"
                ].get("high_severity_high_confidence", 0)
                report.high_severity_low_confidence = priority_matrix[
                    "quadrant_counts"
                ].get("high_severity_low_confidence", 0)
                report.low_severity_high_confidence = priority_matrix[
                    "quadrant_counts"
                ].get("low_severity_high_confidence", 0)
                report.low_severity_low_confidence = priority_matrix[
                    "quadrant_counts"
                ].get("low_severity_low_confidence", 0)

            if ai_summary:
                report.ai_summary_vulnerabilities = ai_summary.get("summary", {}).get(
                    "vulnerabilities", ""
                )
                report.ai_summary_tech = ai_summary.get("summary", {}).get("tech", "")

            _tables.append(report)
            tech_disc = TechDiscovery(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                data=_plugins_dump,
            )
            scan = Scan(
                id=str(uuid.uuid4()),
                report_id=report_id,
                user_id=user_id,
                is_automated=is_automated,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="all",
                scan_type="full scan",
                data=analytics_data["union"],
                crawl_depth=0,
                scan_duration=floor(duration),
                target_url=url,
            )
            _tables.append(tech_disc)
            _tables.append(scan)
            session.add_all(_tables)
            try:
                self._insert_zap_vulnerabilities(
                    report_id, timestamp, zap_raw_data, session
                )
                self._insert_wapiti_vulnerabilities(
                    report_id,
                    timestamp,
                    wapiti_raw_data,
                    session,
                    analytics_data.get("intersection", []),
                )
                self._insert_nuclei_vulnerabilities(
                    report_id, timestamp, nuclei_raw_data, session
                )
                session.commit()
            except Exception as e:
                logger.error(f"Vulnerability insert failed: {e}")
                raise
            return report_id

    def insert_automated_report(
        self,
        timestamp: datetime,
        plugins: list,
        zap_raw_data: dict,
        wapiti_raw_data: dict,
        nuclei_raw_data: dict,
        analytics_data: dict,
        duration: float,
        url,
        session_name: str = None,
    ):
        engine = self._check_engine()
        _tables = []
        _zap_dump = json.dumps(zap_raw_data)
        _wapiti_dump = json.dumps(wapiti_raw_data)
        _plugins_dump = json.dumps(plugins)
        total_union = sum(
            len(scanner_results) for scanner_results in analytics_data["union"]
        )
        total_intersection = len(analytics_data.get("intersection", []))
        total_vulnerabilities = total_union
        with Session(engine) as session:
            report_id = str(uuid.uuid4())
            report = Report(
                id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scan_type="automated",
                scanner="all",
                total_vulnerabilities=total_vulnerabilities,
                critical_count=utils.critical_counter(
                    analytics_data["union"], analytics_data["rules"]
                ),
            )

            # COMPUTE ANALYTICS BEFORE COMMITTING
            if session_name:
                report = compute_and_attach_analytics(
                    report, analytics_data, session_name
                )

            _tables.append(report)
            tech_disc = TechDiscovery(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                data=_plugins_dump,
            )
            scan = Scan(
                id=str(uuid.uuid4()),
                report_id=report_id,
                scan_date=timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="all",
                scan_type="full scan",
                data=analytics_data["union"],
                crawl_depth=0,
                scan_duration=floor(duration),
                target_url=url,
            )
            _tables.append(tech_disc)
            _tables.append(scan)
            session.add_all(_tables)
            try:
                self._insert_zap_vulnerabilities(
                    report_id, timestamp, zap_raw_data, session
                )
                self._insert_wapiti_vulnerabilities(
                    report_id,
                    timestamp,
                    wapiti_raw_data,
                    session,
                    analytics_data.get("intersection", []),
                )
                self._insert_nuclei_vulnerabilities(
                    report_id, timestamp, nuclei_raw_data, session
                )
                session.commit()
            except Exception as e:
                logger.error(f"Vulnerability insert failed: {e}")
                raise

    @staticmethod
    def _insert_zap_vulnerabilities(parent_report_id, scan_time, raw_data, session):
        _entries = []
        _rules = utils.unroll_sarif_rules(raw_data)

        _severity_map = {"error": "High", "warning": "Medium", "note": "Low"}

        for vulnerability in raw_data["runs"][0]["results"]:
            _rule = _rules.get(vulnerability["ruleId"])
            _json_dump = json.dumps(vulnerability)

            # Use SARIF level instead of ZAP's own risk property
            _level = vulnerability.get("level", "note").lower()
            _severity = _severity_map.get(_level, "Informational")

            _vuln = Vulnerability(
                id=str(uuid.uuid4()),
                report_id=parent_report_id,
                scan_date=scan_time.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="zap",
                vulnerability_type=_rule["name"],
                severity=_severity,
                description=_rule["fullDescription"]["text"],
                http_request=json.dumps(vulnerability["properties"]["har"])
                if vulnerability["properties"]["har"] is not None
                else None,
                endpoint=vulnerability["locations"][0]["physicalLocation"][
                    "artifactLocation"
                ]["uri"],
                remediation_effort=_rule["help"]["text"],
                method=vulnerability["properties"]["method"],
                confidence=vulnerability["properties"]["confidence"],
                state="new",
                data=_json_dump,
                is_duplicate=False,
            )
            _entries.append(_vuln)
        session.add_all(_entries)

    @staticmethod
    def _insert_wapiti_vulnerabilities(
        parent_report_id, scan_time, raw_data, session, intersection_list=None
    ):
        _entries = []
        _rules = utils.unroll_sarif_rules(raw_data)

        # Count how many intersection matches exist per endpoint
        # (could be >1 if multiple vulns matched at same endpoint)
        from collections import Counter

        intersection_endpoint_counts = Counter()
        for iv in intersection_list or []:
            ep = iv["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            intersection_endpoint_counts[ep] += 1

        # Track how many wapiti vulns we've already marked per endpoint
        marked_counts = Counter()

        for vulnerability in raw_data["runs"][0]["results"]:
            _rule = _rules.get(vulnerability["ruleId"])
            endpoint = vulnerability["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]["uri"]

            # Only mark as duplicate if we haven't exceeded the intersection count for this endpoint
            is_dup = False
            if intersection_endpoint_counts.get(endpoint, 0) > marked_counts[endpoint]:
                is_dup = True
                marked_counts[endpoint] += 1

            _severity = vulnerability["level"]
            if str.lower(_severity) == "note":
                _severity = "Low"
            elif str.lower(_severity) == "warning":
                _severity = "High"
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
                description=_rule["fullDescription"]["text"],
                severity=_severity,
                http_request=vulnerability["properties"]["http_request"],
                endpoint=endpoint,
                remediation_effort=_rule["help"]["text"],
                method=vulnerability["properties"]["method"],
                state="new",
                confidence="Low",
                data=json.dumps(vulnerability),
                is_duplicate=is_dup,
            )
            _entries.append(_vuln)
        session.add_all(_entries)

    @staticmethod
    def _insert_nuclei_vulnerabilities(
        parent_report_id: str, scan_time: datetime, raw_data: dict, session: Session
    ):
        """Insert Nuclei vulnerabilities from SARIF format"""
        if not raw_data or "runs" not in raw_data or not raw_data["runs"]:
            return

        _entries = []
        _rules = utils.unroll_sarif_rules(raw_data)

        for vulnerability in raw_data["runs"][0]["results"]:
            _rule = _rules.get(vulnerability["ruleId"])
            _json_dump = json.dumps(vulnerability)

            _severity_map = {"note": "Low", "warning": "High", "error": "High"}
            _severity = _severity_map.get(
                vulnerability.get("level", "note").lower(), "Low"
            )

            props = vulnerability.get("properties", {})

            _vuln = Vulnerability(
                id=str(uuid.uuid4()),
                report_id=parent_report_id,
                scan_date=scan_time.strftime("%Y-%m-%d %H:%M:%S"),
                scanner="nuclei",
                vulnerability_type=_rule.get("name", "Unknown"),
                description=_rule.get("fullDescription", {}).get(
                    "text", "No description"
                ),
                severity=props.get("severity", _severity),
                http_request=props.get("curl-command", None),
                endpoint=vulnerability["locations"][0]["physicalLocation"][
                    "artifactLocation"
                ]["uri"],
                remediation_effort=_rule.get("help", {}).get("text", ""),
                method="GET",
                state="new",
                confidence="Medium",
                data=_json_dump,
            )
            _entries.append(_vuln)
        session.add_all(_entries)

    @property
    def engine(self):
        if self._engine is None:
            self._engine = self._check_engine()
        return self._engine

    @deprecated("Should utilize Laravel's ORM")
    def get_report_by_id(self, report_id: str):
        engine = self._check_engine()
        with Session(engine) as session:
            report = session.query(Report).filter(Report.id == report_id).first()
            if not report:
                return None
            result = {
                "id": report.id,
                "scan_date": report.scan_date,
                "scan_type": report.scan_type,
                "scanner": report.scanner.upper() if report.scanner else None,
                "raw_data": report.path,
            }
            return result

    def delete_report(self, report_id: str) -> bool:
        """Delete a report and its associated data from the database"""
        engine = self._check_engine()
        try:
            with Session(engine) as session:
                report = session.query(Report).filter(Report.id == report_id).first()
                if report:
                    session.delete(report)
                    session.commit()
                    return True
                return False
        except Exception as e:
            logger.error(f"Error deleting report: {e}")
            return False


if __name__ == "__main__":
    # 1. Initialize the database handler
    db = Database()

    # 2. (Optional) If you want to wipe the DB first and start fresh:
    # print("Cleaning old tables...")
    # db.clean()

    # 3. Run the migration
    print("Starting database migration...")
    try:
        db.migrate()
        print("Migration successful! Tables created.")
    except Exception as e:
        print(f"Migration failed: {e}")
