from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from utils_zap import active_scan
import json
from config import Config
from utils_zap import limit_ascan
from pymongo import MongoClient

app = FastAPI()

limit_ascan(Config.ZAP_API_KEY)

@app.get("/")
async def index():
    return {"message": "hello"}

@app.post("/active")
async def active(request: Request):
    data = await request.json()
    if 'target' in data:
        target = data['target']
        mongo_uri = Config.MONGO_URI
        db_name = Config.MONGO_DB_NAME
        client = MongoClient(mongo_uri)
        db = client[db_name]
        endpoints = list(db.endpoints.find({}, {'_id': 0, 'path': 1, 'methods': 1}))
        if not endpoints:
            raise HTTPException(status_code=404, detail="No endpoints found")

        # Format endpoints for active_scan function
        formatted_endpoints = [endpoint['path'] for endpoint in endpoints]
        endpoints_json = json.dumps(formatted_endpoints)
        try:
            alertOrNot, result = active_scan(target, endpoints_json)
            return {"message": "active_scan_successful"}
        except Exception as e:
            print(e)
            raise HTTPException(status_code=500, detail="An error occurred during the active scan")
    raise HTTPException(status_code=400, detail="No target found")

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
