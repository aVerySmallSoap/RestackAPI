import asyncio
import os
import sys
from loguru import logger

# 1. Setup paths to ensure modules are found
sys.path.append(os.getcwd())

from modules.db.database import Database
from services.managers.ScheduleManager import ScheduleManager
from modules.utils import __utils__ as utilities

# Ensure directories exist
utilities.check_directories()


async def main():
    logger.info("Starting Dedicated Scheduler Service...")

    try:
        # 2. Initialize dependencies for THIS process
        db = Database()

        # Pass db as positional arg to avoid keyword errors
        schedule_manager = ScheduleManager(db)

        # 3. Load Jobs
        # If this method internally calls scheduler.start(), the next step will handle it.
        scheduler = schedule_manager.initialize_apscheduler_jobs()

        # 4. SAFETY CHECK: Only start if not already running
        if not scheduler.running:
            scheduler.start()
            logger.success("Scheduler started manually.")
        else:
            logger.info("Scheduler was already active (started by Manager).")

        # 5. Keep the service alive
        logger.info("Service is running. Press Ctrl+C to stop.")
        while True:
            await asyncio.sleep(1)

    except (KeyboardInterrupt, SystemExit):
        logger.info("Stopping scheduler...")
        try:
            if 'scheduler' in locals() and scheduler.running:
                scheduler.shutdown()
        except Exception:
            pass
    except Exception as e:
        logger.exception(f"Scheduler Service Crashed: {e}")


if __name__ == "__main__":
    asyncio.run(main())