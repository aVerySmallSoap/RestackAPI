from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], #TODO: Fetch security certs and allow only a single origin
    allow_methods=["*"],
)

@app.get("/api/v1/wapiti/scan")
async def wapiti_scan(url: str):
    pass

@app.get("/api/v1/wapiti/report/{report_id}")
async def wapiti_report(report_id: str):
    pass

@app.get("/api/v1/whatweb/scan")
async def whatweb_scan(url: str):
    pass

if __name__ == '__main__':
    pass