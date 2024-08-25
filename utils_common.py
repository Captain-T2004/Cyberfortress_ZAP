import string
import random
from pymongo import MongoClient
from config import Config
def generate_random(length):
    res = ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))
    return res

def save_scan_results_to_db(all_alerts):
    try:
        # Connect to MongoDB\
        mongo_uri = Config.MONGO_URI
        db_name = Config.MONGO_DB_NAME
        collection_name = Config.MONGO_COLLECTION_NAME
        client = MongoClient(mongo_uri)
        db = client[db_name]
        collection = db[collection_name]
        
        for endpoint, alerts in all_alerts.items():            
            # Update the document if it exists, or insert it if it doesn't
            result = collection.update_one(
                {"path": endpoint},  # Find the document with the matching path
                {
                    "$set": {
                        "alerts": alerts,  # Update the alerts with the list of alert dictionaries
                    }
                },
                upsert=True  # Insert the document if it doesn't exist
            )
            if result.matched_count > 0:
                print(f"Updated existing document for path: {endpoint}")
            else:
                print(f"Inserted new document for path: {endpoint}")
            
        client.close()
        print("Scan results saved to MongoDB.")

    except Exception as e:
        print(f"Error saving scan results to MongoDB: {str(e)}")