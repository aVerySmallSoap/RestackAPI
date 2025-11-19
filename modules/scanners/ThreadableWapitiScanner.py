from modules.interfaces.IThreadableScannerAdapter import IThreadableScannerAdapter


class ThreadableWapitiScanner(IThreadableScannerAdapter):

    async def start_scan(self, config: dict):
        pass

    def stop_scan(self):
        pass

    async def parse_results(self, config: dict):
        pass