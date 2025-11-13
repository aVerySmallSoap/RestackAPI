# Generate reports based on system results
# The systems generates PDF and Excel
# STRUCTURE
# NUMBER OF VULNERABILITIES DETECTED || Should be filtered with medium risk
# AI SUMMARY OF RESULTS
# AI RECOMMENDATIONS BASED ON RESULTS
# SCAN DETAILS || i.e., DOMAIN , IP ADDRESS , SERVER OS (if found), TOOLS USED, TOTAL SCAN TIME, SCAN DATE, SCAN TYPE
# INFORMATION TABLE
# TECHNOLOGIES FINGERPRINTED || TECHNOLOGY | VERSION | IS_VULNERABLE | CVE's
# VULNERABILITIES TABLE || Results should also be filtered with medium risk as to not overpopulate the table
# VULNERABILITIES || TYPE | CVE's | TOOL | ENDPOINT | CONFIDENCE | RISK

def generate_excel(report_id:str):
    pass

def generate_pdf(report_id:str):
    pass