# scheduler_service.py
import asyncio
import os
from loguru import logger

# Import your modules
from modules.db.database import Database
from services.managers.ScheduleManager import ScheduleManager
from modules.utils import __utils__ as utilities

# Ensure directories exist
utilities.check_directories()

async def main():
    logger.info("Starting Dedicated Scheduler Service...")

    # 1. Initialize dependencies
    # We create new instances here because this is a separate process
    db = Database()

    # 2. Initialize Schedule Manager
    schedule_manager = ScheduleManager(database=db)

    # 3. Load Jobs & Start Scheduler
    # We pass the dependencies so the jobs can use them (if needed by your logic)
    scheduler = schedule_manager.initialize_apscheduler_jobs()

    # 4. START the scheduler (Only happens in this process)
    scheduler.start()
    logger.success("Scheduler started! Press Ctrl+C to exit.")

    # 5. Keep the process alive
    try:
        # Run forever
        while True:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Stopping scheduler...")
        scheduler.shutdown()


if __name__ == "__main__":
    asyncio.run(main())