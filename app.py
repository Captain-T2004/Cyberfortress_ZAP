from flask import Flask, render_template, jsonify, request, redirect
from utils_zap import active_scan
import json
from config import Config
from utils_zap import limit_ascan, report
from zapv2 import ZAPv2
from pymongo import MongoClient
app = Flask(__name__,static_url_path='/static')

limit_ascan(Config.ZAP_API_KEY)

@app.route('/')
def index():
    return jsonify({'message':'hello'})

@app.route('/active')
def active():
    data = request.json
    if('target' in data):
        target = data['target']
        mongo_uri = Config.MONGO_URI
        db_name = Config.MONGO_DB_NAME
        client = MongoClient(mongo_uri)
        db = client[db_name]
        endpoints = list(db.endpoints.find({}, {'_id': 0, 'path': 1, 'methods': 1}))
        if not endpoints:
            return jsonify({'message': 'No endpoints found'})

        # Format endpoints for active_scan function
        formatted_endpoints = [endpoint['path'] for endpoint in endpoints]
        endpoints_json = json.dumps(formatted_endpoints)
        try:
            alertOrNot, result = active_scan(target,endpoints_json)
            return jsonify({'message':'active_scan_successful'})
        except Exception as e:
            print(e)
            return jsonify({'message':'No target found'})
    return jsonify({'message':'No target found'})

if __name__ == '__main__':
    app.run()