import asyncio
import os
import sys
from loguru import logger
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from modules.db.database import Database
from services.managers.ScheduleManager import ScheduleManager
from modules.utils import __utils__ as utilities
from modules.utils.background_runnable import run_scheduled_scan

# 1. Setup paths to ensure modules are found
sys.path.append(os.getcwd())
# Ensure directories exist
utilities.check_directories()


async def poll_for_schedule_changes(schedule_manager: ScheduleManager, scheduler):
    """
    Poll database every 30 seconds for:
    - New schedules to add
    - Deleted schedules to remove
    - Updated schedules to reschedule
    """
    logger.info("Starting schedule polling service...")

    # Track last known state
    last_known_schedules = {}

    while True:
        try:
            await asyncio.sleep(30)  # Poll every 30 seconds
            logger.debug("Polling for schedule changes...")

            # Fetch current schedules from database
            db_schedules = schedule_manager._fetch_schedules_from_db()
            current_schedules = {str(s['id']): s for s in db_schedules}
            current_ids = set(current_schedules.keys())

            # Get scheduler jobs
            scheduler_jobs = {job.id: job for job in scheduler.get_jobs()}
            scheduler_ids = set(scheduler_jobs.keys())

            # === DETECT NEW SCHEDULES ===
            new_schedule_ids = current_ids - scheduler_ids
            for schedule_id in new_schedule_ids:
                schedule = current_schedules[schedule_id]
                logger.info(f"🆕 New schedule detected: {schedule['name']} ({schedule_id})")

                try:
                    # Create trigger
                    if schedule["type"] == "interval":
                        trigger = IntervalTrigger(**schedule["config"])
                    elif schedule["type"] == "cron":
                        trigger = CronTrigger(**schedule["config"])
                    else:
                        logger.error(f"Invalid job type: {schedule['type']}")
                        continue

                    # Add job to scheduler
                    scheduler.add_job(
                        run_scheduled_scan,
                        trigger=trigger,
                        id=schedule_id,
                        name=schedule["name"],
                        args=[schedule["url"]],
                        replace_existing=False,
                        jobstore='default'
                    )
                    logger.success(f"✅ Added schedule: {schedule['name']}")

                except Exception as e:
                    logger.error(f"Failed to add schedule {schedule_id}: {e}")

            # === DETECT DELETED SCHEDULES ===
            deleted_schedule_ids = scheduler_ids - current_ids
            for schedule_id in deleted_schedule_ids:
                job = scheduler_jobs[schedule_id]
                logger.info(f"🗑️  Deleted schedule detected: {job.name} ({schedule_id})")

                try:
                    scheduler.remove_job(schedule_id, jobstore='default')
                    logger.success(f"✅ Removed schedule: {job.name}")
                except Exception as e:
                    logger.error(f"Failed to remove schedule {schedule_id}: {e}")

            # === DETECT UPDATED SCHEDULES ===
            common_ids = current_ids & scheduler_ids
            for schedule_id in common_ids:
                current_schedule = current_schedules[schedule_id]

                # Check if this schedule changed since last poll
                if schedule_id in last_known_schedules:
                    last_schedule = last_known_schedules[schedule_id]

                    # Compare relevant fields
                    changed = (
                            current_schedule['name'] != last_schedule['name'] or
                            current_schedule['url'] != last_schedule['url'] or
                            current_schedule['type'] != last_schedule['type'] or
                            current_schedule['config'] != last_schedule['config']
                    )

                    if changed:
                        logger.info(f"🔄 Updated schedule detected: {current_schedule['name']} ({schedule_id})")

                        try:
                            # Create new trigger
                            if current_schedule["type"] == "interval":
                                new_trigger = IntervalTrigger(**current_schedule["config"])
                            elif current_schedule["type"] == "cron":
                                new_trigger = CronTrigger(**current_schedule["config"])
                            else:
                                logger.error(f"Invalid job type: {current_schedule['type']}")
                                continue

                            # Reschedule job
                            scheduler.reschedule_job(
                                schedule_id,
                                jobstore='default',
                                trigger=new_trigger
                            )

                            # Update job metadata (name, args)
                            scheduler.modify_job(
                                schedule_id,
                                jobstore='default',
                                name=current_schedule["name"],
                                args=[current_schedule["url"]]
                            )

                            logger.success(f"✅ Updated schedule: {current_schedule['name']}")

                        except Exception as e:
                            logger.error(f"Failed to update schedule {schedule_id}: {e}")

            # Update last known state
            last_known_schedules = current_schedules.copy()

            logger.debug(f"Polling complete. Active schedules: {len(current_schedules)}")

        except Exception as e:
            logger.error(f"Error in polling loop: {e}")
            # Continue polling even if there's an error


async def main():
    logger.info("Starting Dedicated Scheduler Service...")

    poll_task = None
    try:
        # Initialize dependencies
        db = Database()
        schedule_manager = ScheduleManager(db)

        # Load existing jobs and start scheduler
        scheduler = schedule_manager.initialize_apscheduler_jobs()

        if not scheduler.running:
            scheduler.start()
            logger.success("✅ Scheduler started successfully")

        # Start background polling task
        poll_task = asyncio.create_task(
            poll_for_schedule_changes(schedule_manager, scheduler)
        )

        logger.info("📡 Service is running. Press Ctrl+C to stop.")
        logger.info(f"🔍 Polling interval: 30 seconds")

        # Keep service alive
        while True:
            await asyncio.sleep(1)

    except (KeyboardInterrupt, SystemExit):
        logger.info("🛑 Stopping scheduler service...")
        if poll_task:
            poll_task.cancel()
            try:
                await poll_task
            except asyncio.CancelledError:
                pass
        if scheduler and scheduler.running:
            scheduler.shutdown()
        logger.info("✅ Scheduler stopped")
    except Exception as e:
        logger.exception(f"❌ Scheduler Service Crashed: {e}")


if __name__ == "__main__":
    asyncio.run(main())