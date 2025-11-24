import asyncio

import modules.utils.__utils__ as utilities
from modules.interfaces.enums.restack_enums import ScanStep
from fastapi import WebSocket, WebSocketDisconnect


class ScanTracker:

    def __init__(self):
        self.active_scans = {}

    def add_scan(self, session:str, target:str, step:ScanStep):
        if session in self.active_scans:
            return
        self.active_scans.update({
            session: {
                "session": session,
                "target": target,
                "step": step
            }
        })
        print(self.active_scans)
        return


    def remove_scan(self, session:str):
        self.active_scans.pop(session)

    def fetch_scan(self, session:str) -> dict:
        return self.active_scans.get(session)

    def fetch_all_scans(self) -> dict:
        if len(self.active_scans) == 0:
            return {"message": "There are no scans"}
        return self.active_scans

    def advance_step(self, session:str, step:ScanStep):
        """
        Changes what step the tracked scan is in.
        """
        self.active_scans[session]["step"] = step

    def generate_unique_session(self) -> str:
        _session = utilities.generate_random_uuid()
        if len(self.active_scans) == 0:
            return _session
        while _session in self.active_scans:
            _session = utilities.generate_random_uuid()
        return _session

    async def send_scan_tracking_heartbeat(self, websocket: WebSocket):
        while True:
            await asyncio.sleep(5)
            print(self.active_scans)
            try:
                await websocket.send_json(self.fetch_all_scans())
            except WebSocketDisconnect:
                break