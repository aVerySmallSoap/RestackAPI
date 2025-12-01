import uuid
import time
from datetime import datetime
from sqlalchemy.orm import Session

# Import your database and models
from services.FileReportGenerator import db, generate_excel
from modules.db.database import Report
from modules.db.table_collection import Scan, TechDiscovery, Vulnerability

# This is the test ID we will use
TEST_REPORT_ID = str(uuid.uuid4())


def setup_test_data():
    """Connects to the DB, creates schema, and adds mock data."""
    print(f"Setting up test data for report ID: {TEST_REPORT_ID}")

    # Ensure all tables are created
    db.migrate()

    with Session(db.engine) as session:
        # 1. Main Report
        report = Report(
            id=TEST_REPORT_ID,
            scan_date=datetime.now(),
            scanner="all",
            scan_type="manual test",
            path="/fake/path.json",
            total_vulnerabilities=3,
            critical_count=1
        )

        # 2. Scan Details
        scan = Scan(
            id=str(uuid.uuid4()),
            report_id=TEST_REPORT_ID,
            scan_date=datetime.now(),
            scanner="all",
            scan_type="manual test",
            scan_duration=120.5,
            crawl_depth=10,
            target_url="http://test.com",
            data={"info": "manual test data"}  # Added test data
        )

        # 3. Tech Discovery
        tech_data = [
            [{"Apache": "2.4.5"}],  # versioned
            [{"React": {}}],  # unversioned
            [], [], []
        ]
        tech = TechDiscovery(
            id=str(uuid.uuid4()),
            report_id=TEST_REPORT_ID,
            scan_date=datetime.now(),
            data=tech_data
        )

        # 4. Vulnerabilities (to test filtering)
        vuln_high = Vulnerability(
            id=str(uuid.uuid4()), report_id=TEST_REPORT_ID, scan_date=datetime.now(),
            scanner="zap", vulnerability_type="SQL Injection", severity="High",
            confidence="High", endpoint="/login", description="SQLi found",
            remediation_effort="High", method="POST", state="new", data={}
        )
        vuln_med = Vulnerability(
            id=str(uuid.uuid4()), report_id=TEST_REPORT_ID, scan_date=datetime.now(),
            scanner="wapiti", vulnerability_type="XSS", severity="Medium",
            confidence="Medium", endpoint="/search", description="XSS found",
            remediation_effort="Medium", method="GET", state="new", data={}
        )
        vuln_low = Vulnerability(
            id=str(uuid.uuid4()), report_id=TEST_REPORT_ID, scan_date=datetime.now(),
            scanner="zap", vulnerability_type="Info Leak", severity="Low",
            confidence="Low", endpoint="/", description="Info leak",
            remediation_effort="Low", method="GET", state="new", data={}
        )

        session.add_all([report, scan, tech, vuln_high, vuln_med, vuln_low])
        session.commit()
    print("Test data populated successfully.")


def run_test():
    """Runs the report generator and prints the file path."""
    print("\nRunning generate_excel()...")
    result = generate_excel(TEST_REPORT_ID)

    if "path" in result:
        print("\n--- SCRIPT SUCCESS ---")
        print(f"File generated successfully!")
        print(f"You can open it here: {result['path']}")
    else:
        print(f"Error generating report: {result}")


def cleanup_data():
    """Removes the mock data from the database."""
    print("\nCleaning up test data...")
    with Session(db.engine) as session:
        # Find the parent Report object
        report = session.get(Report, TEST_REPORT_ID)
        if report:
            # Delete it. The cascade will delete all related objects.
            session.delete(report)
            session.commit()
            print("Cleanup complete.")
        else:
            print("Could not find test data to clean up.")


if __name__ == "__main__":
    try:
        setup_test_data()
        time.sleep(1)  # Just to make the process feel clearer
        run_test()
    except Exception as e:
        print(f"\nAn error occurred: {e}")
    finally:
        # Always run cleanup
        time.sleep(1)
        cleanup_data()