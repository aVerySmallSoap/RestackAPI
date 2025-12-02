# services/ScanTracker.py
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import select, delete
from loguru import logger

from modules.db.table_collection import ActiveScan
from modules.interfaces.enums.restack_enums import ScanStep
import modules.utils.__utils__ as utilities


class ScanTracker:
    def __init__(self):
        from modules.db.database import Database
        self._db = Database()

    def add_scan(self, session_id: str, target: str, step: ScanStep):
        """Insert a new active scan into the DB"""
        try:
            with Session(self._db.engine) as session:
                new_scan = ActiveScan(
                    session_id=session_id,
                    target=target,
                    step=step.value,
                    start_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
                session.add(new_scan)
                session.commit()
                logger.debug(f"Scan {session_id} added to tracker.")
        except Exception as e:
            logger.error(f"Failed to add scan to tracker: {e}")

    def remove_scan(self, session_id: str):
        """Remove a scan from the DB (Scan completed or failed)"""
        try:
            with Session(self._db.engine) as session:
                statement = delete(ActiveScan).where(ActiveScan.session_id == session_id)
                session.execute(statement)
                session.commit()
                logger.debug(f"Scan {session_id} removed from tracker.")
        except Exception as e:
            logger.error(f"Failed to remove scan from tracker: {e}")

    def fetch_scan(self, session_id: str) -> dict:
        with Session(self._db.engine) as session:
            scan = session.scalar(select(ActiveScan).where(ActiveScan.session_id == session_id))
            if scan:
                return {
                    "session": scan.session_id,
                    "target": scan.target,
                    "step": scan.step
                }
            return {}

    def fetch_all_scans(self) -> dict:
        """Returns a dict format compatible with your frontend"""
        results = {}
        with Session(self._db.engine) as session:
            scans = session.scalars(select(ActiveScan)).all()
            if not scans:
                return {}  # Return empty to indicate no scans

            for scan in scans:
                results[scan.session_id] = {
                    "session": scan.session_id,
                    "target": scan.target,
                    "step": scan.step
                }
        return results

    def advance_step(self, session_id: str, step: ScanStep):
        """Update the step of a specific scan"""
        try:
            with Session(self._db.engine) as session:
                scan = session.scalar(select(ActiveScan).where(ActiveScan.session_id == session_id))
                if scan:
                    scan.step = step.value
                    session.commit()
        except Exception as e:
            logger.error(f"Failed to advance step for {session_id}: {e}")

    def generate_unique_session(self) -> str:
        # Since we use UUIDs and DB constraints, we can just generate one.
        # Collisions are mathematically impossible for this scale.
        return utilities.generate_random_uuid()