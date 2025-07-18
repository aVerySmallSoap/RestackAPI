from datetime import datetime

class ReportManager:
    """Manages the naming and local paths of generated reports."""
    _local_path:str = "reports/" # Reference path in which reports are stored
    _reports:list = [] # This array should only store a dict that has two values, path and name, wherein name is the name of the report
    pointer:int = 0 # points to the current report being watched | temporary db solution

    def __init__(self):
        pass

    def generate(self, date: str|datetime):
        """Generates a name and path for the report. The naming scheme is: YYYYMMDD_HH-SS"""
        if type(date) == type(datetime):
            date = date.strftime("%Y%m%d_%I-%M-%S")
        tmp:list = [self._local_path, date]
        if len(self._reports) > 0: #increment pointer only if there is one report
            self.pointer+=1
        self._reports.append(tmp)

    def build(self):
        """Builds the filepath for wapiti"""
        file = self._reports[self.pointer]
        path:str = ""
        for item in file:
            path += item
        path += ".json"
        return path