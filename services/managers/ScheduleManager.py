import json
import uuid  # Manage Scheduled Scans
# Type of scan | Target | Config | Time of execution
# Results: Scan Data -> Database | Scan time | Errors
# Finally: Let the data be fetchable from the database
# Related tables: table_collection.ScheduledScans
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from loguru import logger
from sqlalchemy.orm import Session

from modules.db.database import Database
from sqlalchemy import create_engine
from modules.db.table_collection import ScheduledScans
from modules.utils.background_runnable import run_scheduled_scan


class ScheduleManager:
    _database = None

    def __init__(self, database: Database):
        self._database = database
        self._jobs_engine = create_engine("postgresql://postgres:root@localhost:5432/restack_schedules")
        _jobstore = {
            'default': SQLAlchemyJobStore(engine=self._jobs_engine)
        }
        self._scheduler = AsyncIOScheduler(jobstores=_jobstore)

    def _fetch_schedules_from_db(self) -> list:
        logger.debug("Fetching schedules from the database")
        engine = self._database.engine
        _returnable = []
        with Session(engine) as session:
            rows = session.query(ScheduledScans).all()
            if rows is None or len(rows) == 0:
                return []
            for row in rows:
                # If interval is datatime then parse it out, else, just use it
                _returnable.append(
                    {
                        "id": row.id,
                        "type": row.job_type,
                        "config": row.configuration,
                        "url": row.url,
                        "name": row.codename
                    }
                )
            return _returnable

    def _fetch_stored_jobs(self):
        logger.debug("Fetching stored jobs from the database")
        engine = self._jobs_engine.engine
        self._scheduler.get_jobs()
        _returnable = []
        with Session(engine) as session:
            return session.query().all()

    def initialize_apscheduler_jobs(self, scan_tracker) -> AsyncIOScheduler:
        logger.debug("Initializing scheduled jobs")
        _schedules = self._fetch_schedules_from_db()

        # It's often safer to rely on the scheduler's internal store than fetching manually
        # _stored_jobs = self._fetch_stored_jobs()

        if not _schedules:
            return self._scheduler

        for schedule in _schedules:
            job_id = schedule["id"]

            # 1. Define the trigger
            if schedule["type"] == "interval":
                new_trigger = IntervalTrigger(**schedule["config"])
            elif schedule["type"] == "cron":
                new_trigger = CronTrigger(**schedule["config"])
            else:
                continue  # Skip invalid types

            # 2. Add or Update the job in one step
            # 'replace_existing=True' prevents "Job already exists" errors
            # and automatically updates the job if the trigger/args changed.
            try:
                self._scheduler.add_job(
                    run_scheduled_scan,
                    trigger=new_trigger,
                    id=job_id,
                    name=schedule["name"],
                    # CRITICAL FIX: Do not pass self._scanner_manager.
                    # Only pass the simple string URL.
                    args=[schedule["url"]],
                    replace_existing=True,
                    jobstore='default'
                )
            except Exception as e:
                logger.error(f"Failed to schedule job {job_id}: {e}")
        return self._scheduler

    def add_schedule_scan(self, name: str, interval_type: str, target: str, interval: dict):
        schedule_id: str = str(uuid.uuid4())
        if interval_type == "interval":
            new_trigger = IntervalTrigger(**interval)
        elif interval_type == "cron":
            new_trigger = CronTrigger(**interval)
        else:
            new_trigger = None
        self._scheduler.add_job(
            run_scheduled_scan,
            trigger=new_trigger,
            id=schedule_id,
            # CRITICAL FIX: Only pass the target string
            args=[target],
            replace_existing=True
        )
        engine = self._database.engine
        with Session(engine) as session:
            new_scan = ScheduledScans(
                id=schedule_id,
                url=target,
                codename=name,
                job_type=interval_type,
                configuration=interval,
            )
            session.add_all([new_scan])
            session.commit()
            session.close()

    async def poll_for_changes(self):
        pass # Not yet implemented