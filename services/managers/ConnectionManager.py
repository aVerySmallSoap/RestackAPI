from fastapi import WebSocket, WebSocketDisconnect


class ConnectionManager:

    def __init__(self):
        self.active_connections:list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

connection_manager = ConnectionManager()