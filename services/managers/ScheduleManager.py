#Manage Scheduled Scans
# Type of scan | Target | Config | Time of execution
# Results: Scan Data -> Database | Scan time | Errors
# Finally: Let the data be fetchable from the database
# Related tables: table_collection.ScheduledScans
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from sqlalchemy.orm import Session
from loguru import logger

from modules.db.database import Database
from modules.db.table_collection import ScheduledScans
from modules.utils.background_runnable import scheduled_scan


class ScheduleManager:

    _database = None
    _scheduler = AsyncIOScheduler()

    def __init__(self, database: Database):
        self._database = database

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


    def initialize_apscheduler_jobs(self, scanner_engine, database) -> AsyncIOScheduler:
        logger.debug("Initializing scheduled jobs")
        _schedules = self._fetch_schedules_from_db()
        if _schedules is None or len(_schedules) == 0:
            return self._scheduler
        for schedule in _schedules:
            job_id = schedule["id"]

            # Check if the job type is an interval or cron
            if schedule["type"] == "interval":
                new_trigger = IntervalTrigger(**schedule["config"])
            elif schedule["type"] == "cron":
                new_trigger = CronTrigger(**schedule["config"])
            else:
                new_trigger = None

            existing_job = self._scheduler.get_job(job_id)
            if existing_job is None:
                self._scheduler.add_job(
                    scheduled_scan,
                    trigger=new_trigger,
                    id=job_id,
                    name=schedule["name"],
                    args=[scanner_engine, schedule["url"], database],
                )
            else:
                #Job exists
                current_trigger = existing_job.trigger
                if current_trigger != new_trigger: # trigger is new, update the job
                    self._scheduler.add_job(
                        scheduled_scan,
                        trigger=new_trigger,
                        id=job_id,
                        args=[scanner_engine, schedule["url"], database],
                        replace_existing=True,
                    )
                else: # else ignore
                    #log
                    print()
        return self._scheduler