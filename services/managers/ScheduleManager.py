import uuid
import logging
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from loguru import logger
from sqlalchemy.orm import Session
from sqlalchemy import delete

# Import your models
from modules.db.table_collection import ScheduledScans
from modules.utils.background_runnable import run_scheduled_scan


class ScheduleManager:
    _scheduler = None
    _database = None

    def __init__(self, database):
        self._database = database

        # Configure the JobStore to use PostgreSQL.
        jobstores = {
            'default': SQLAlchemyJobStore(
                url="postgresql+psycopg2://postgres:root@localhost:5432/restack_schedules"
            )
        }

        # Initialize scheduler with the shared jobstore
        self._scheduler = AsyncIOScheduler(jobstores=jobstores)

    def _fetch_schedules_from_db(self) -> list:
        logger.debug("Fetching schedules from the database")
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
            self._scheduler.start()
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

            try:
                self._scheduler.add_job(
                    run_scheduled_scan,
                    trigger=new_trigger,
                    id=job_id,
                    name=schedule["name"],
                    args=[schedule["url"]],
                    replace_existing=True,
                    jobstore='default'
                )
            except Exception as e:
                logger.error(f"Error scheduling job {job_id}: {e}")

        self._scheduler.start()
        return self._scheduler

    def add_schedule_scan(self, name: str, interval_type: str, target: str, interval: dict):
        """Add a new scheduled scan"""
        schedule_id: str = str(uuid.uuid4())

        if interval_type == "interval":
            new_trigger = IntervalTrigger(**interval)
        elif interval_type == "cron":
            new_trigger = CronTrigger(**interval)
        else:
            raise ValueError("Invalid interval type. Must be 'interval' or 'cron'")

        # Add to Scheduler (Syncs to DB automatically via JobStore)
        self._scheduler.add_job(
            run_scheduled_scan,
            trigger=new_trigger,
            id=schedule_id,
            name=name,
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

        logger.info(f"Successfully added schedule: {name} ({schedule_id})")
        return schedule_id

    def delete_schedule(self, schedule_id: str):
        """Removes a schedule from APScheduler and the Database"""
        engine = self._database.engine

        # First check if the schedule exists in the database
        with Session(engine) as session:
            scan = session.query(ScheduledScans).filter(
                ScheduledScans.id == schedule_id
            ).first()

            if not scan:
                logger.warning(f"Schedule {schedule_id} not found in database")
                raise ValueError(f"Schedule {schedule_id} not found")

        try:
            # 1. Remove from APScheduler
            if self._scheduler.get_job(schedule_id, jobstore='default'):
                self._scheduler.remove_job(schedule_id, jobstore='default')
                logger.info(f"Removed job {schedule_id} from APScheduler")
            else:
                logger.warning(f"Job {schedule_id} not found in APScheduler, continuing with database deletion")

            # 2. Remove from Custom Database Table
            with Session(engine) as session:
                result = session.execute(
                    delete(ScheduledScans).where(ScheduledScans.id == schedule_id)
                )
                session.commit()

                if result.rowcount == 0:
                    logger.error(f"Failed to delete schedule {schedule_id} from database")
                    raise ValueError(f"Failed to delete schedule {schedule_id}")

            logger.info(f"Successfully deleted schedule {schedule_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete schedule {schedule_id}: {e}")
            raise e

    def update_schedule(self, schedule_id: str, name: str, interval_type: str, target: str, interval: dict):
        """Updates an existing schedule's trigger and metadata"""
        engine = self._database.engine

        # First verify the schedule exists
        with Session(engine) as session:
            scan = session.query(ScheduledScans).filter(
                ScheduledScans.id == schedule_id
            ).first()

            if not scan:
                logger.error(f"Schedule {schedule_id} not found in database")
                raise ValueError(f"Schedule {schedule_id} not found")

        try:
            # 1. Create new trigger
            if interval_type == "interval":
                new_trigger = IntervalTrigger(**interval)
            elif interval_type == "cron":
                new_trigger = CronTrigger(**interval)
            else:
                raise ValueError("Invalid interval type. Must be 'interval' or 'cron'")

            # 2. Update APScheduler Job
            existing_job = self._scheduler.get_job(schedule_id, jobstore='default')

            if existing_job:
                # Reschedule with new trigger
                self._scheduler.reschedule_job(
                    schedule_id,
                    jobstore='default',
                    trigger=new_trigger
                )
                # Update job name and args
                self._scheduler.modify_job(
                    schedule_id,
                    jobstore='default',
                    name=name,
                    args=[target]
                )
                logger.info(f"Updated existing job {schedule_id} in APScheduler")
            else:
                # If job missing from scheduler but exists in DB, recreate it
                logger.warning(f"Job {schedule_id} not found in scheduler, recreating...")
                self._scheduler.add_job(
                    run_scheduled_scan,
                    trigger=new_trigger,
                    id=schedule_id,
                    name=name,
                    args=[target],
                    replace_existing=True,
                    jobstore='default'
                )

            # 3. Update Database
            with Session(engine) as session:
                scan = session.query(ScheduledScans).filter(
                    ScheduledScans.id == schedule_id
                ).first()

                if scan:
                    scan.codename = name
                    scan.url = target
                    scan.job_type = interval_type
                    scan.configuration = interval
                    session.commit()
                    logger.info(f"Updated schedule {schedule_id} in database")
                else:
                    logger.error(f"Schedule {schedule_id} not found in database during update")
                    raise ValueError(f"Schedule {schedule_id} not found in database")

            logger.info(f"Successfully updated schedule {schedule_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to update schedule {schedule_id}: {e}")
            raise e

    def get_schedule(self, schedule_id: str):
        """Get a single schedule by ID"""
        engine = self._database.engine
        with Session(engine) as session:
            scan = session.query(ScheduledScans).filter(
                ScheduledScans.id == schedule_id
            ).first()

            if not scan:
                return None

            return {
                "id": scan.id,
                "codename": scan.codename,
                "url": scan.url,
                "job_type": scan.job_type,
                "configuration": scan.configuration
            }

    async def poll_for_changes(self):
        """Poll for changes in scheduled scans (placeholder for future implementation)"""
        pass