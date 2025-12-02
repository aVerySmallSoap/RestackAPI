import uuid
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from loguru import logger
from sqlalchemy.orm import Session

# Import your models
from modules.db.table_collection import ScheduledScans
from modules.utils.background_runnable import run_scheduled_scan


class ScheduleManager:
    # 1. Do not instantiate the scheduler at the class level.
    #    Instantiate it in __init__ so we can pass the jobstore config.
    _scheduler = None
    _database = None

    def __init__(self, database):
        self._database = database

        # 2. Configure the JobStore to use PostgreSQL.
        #    This is CRITICAL. This URL must use a synchronous driver (psycopg2).
        #    Do NOT use the '+asyncpg' driver here.
        jobstores = {
            'default': SQLAlchemyJobStore(
                url="postgresql+psycopg2://postgres:root@localhost:5432/restack_schedules"
            )
        }

        # 3. Initialize scheduler with the shared jobstore
        self._scheduler = AsyncIOScheduler(jobstores=jobstores)

    def _fetch_schedules_from_db(self) -> list:
        logger.debug("Fetching schedules from the database")
        # Use your existing database engine for reading config
        engine = self._database.engine
        _returnable = []
        with Session(engine) as session:
            rows = session.query(ScheduledScans).all()
            if rows is None or len(rows) == 0:
                return []
            for row in rows:
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

    def initialize_apscheduler_jobs(self) -> AsyncIOScheduler:
        logger.debug("Initializing scheduled jobs")
        _schedules = self._fetch_schedules_from_db()

        if not _schedules:
            return self._scheduler

        for schedule in _schedules:
            job_id = schedule["id"]

            # Create Trigger
            if schedule["type"] == "interval":
                new_trigger = IntervalTrigger(**schedule["config"])
            elif schedule["type"] == "cron":
                new_trigger = CronTrigger(**schedule["config"])
            else:
                continue

            # 4. Add the job using replace_existing=True.
            #    Because we use SQLAlchemyJobStore, all 4 workers will try to add this.
            #    'replace_existing=True' ensures they just update the same single row in Postgres
            #    instead of creating duplicates.
            try:
                self._scheduler.add_job(
                    run_scheduled_scan,
                    trigger=new_trigger,
                    id=job_id,
                    name=schedule["name"],
                    # Pass ONLY strings/IDs to avoid Pickle errors
                    args=[schedule["url"]],
                    replace_existing=True,
                    jobstore='default'
                )
            except Exception as e:
                logger.error(f"Error scheduling job {job_id}: {e}")

        return self._scheduler

    def add_schedule_scan(self, name: str, interval_type: str, target: str, interval: dict):
        schedule_id: str = str(uuid.uuid4())

        if interval_type == "interval":
            new_trigger = IntervalTrigger(**interval)
        elif interval_type == "cron":
            new_trigger = CronTrigger(**interval)
        else:
            return

        # Add to Scheduler (Syncs to DB automatically via JobStore)
        self._scheduler.add_job(
            run_scheduled_scan,
            trigger=new_trigger,
            id=schedule_id,
            args=[target],
            replace_existing=True,
            jobstore='default'
        )

        # Save metadata to your custom table (for UI/Fetching)
        engine = self._database.engine
        with Session(engine) as session:
            new_scan = ScheduledScans(
                id=schedule_id,
                url=target,
                codename=name,
                job_type=interval_type,
                configuration=interval,
            )
            session.add(new_scan)
            session.commit()

    async def poll_for_changes(self):
        pass