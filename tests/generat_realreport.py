import sys
from sqlalchemy.orm import Session
from sqlalchemy import select

# Import the function, the db instance, and the Report model
from services.FileReportGenerator import generate_excel, db, generate_pdf
from modules.db.table_collection import Report


def main():
    print("Connecting to database to fetch available reports...")

    reports = []
    try:
        with Session(db.engine) as session:
            # Fetch all reports from the database
            results = session.execute(select(Report.id, Report.scan_type, Report.scan_date)).all()

            if not results:
                print("\n--- ERROR ---")
                print("No reports found in the database.")
                print("Please run a scan first to create data.")
                return

            print("\n--- Available Reports ---")
            for index, (id, scan_type, scan_date) in enumerate(results):
                # Store the id to be referenced by its index
                reports.append(id)
                print(f"  {index + 1}: {scan_type} (Date: {scan_date}, ID: {id})")

    except Exception as e:
        print(f"\n--- ERROR ---")
        print(f"Error connecting to DB or fetching reports: {e}")
        return

    print("---------------------------")

    try:
        # Ask the user to pick a report
        choice_str = input("Enter the number of the report you want to generate: ")
        choice_int = int(choice_str) - 1  # Convert 1-based number to 0-based index

        # Validate the choice
        if 0 <= choice_int < len(reports):
            selected_id = reports[choice_int]
            print(f"\nGenerating report for ID: {selected_id}...")

            # Run the function with the selected ID
            result = generate_excel(selected_id)
            resultPDF = generate_pdf(selected_id)

            if "path" in result:
                print("\n--- SCRIPT SUCCESS ---")
                print(f"File generated successfully!")
                print(f"You can open it here: {result['path']}. {resultPDF['path']}")
            else:
                print(f"\n--- ERROR ---")
                print(f"Error generating report: {result}")
        else:
            print(f"\nError: Invalid choice '{choice_str}'.")

    except ValueError:
        print("\nError: Please enter a valid number.")
    except Exception as e:
        print(f"\nAn error occurred: {e}")


if __name__ == "__main__":
    main()