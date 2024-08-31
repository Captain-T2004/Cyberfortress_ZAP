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
            collection.update_one(
                {"path": endpoint},
                {"$set": {"alerts": []}},  # Initialize 'alerts' as an empty list if it doesn't exist
                upsert=True
            )

            # Append the new alerts to the existing alerts list
            result = collection.update_one(
                {"path": endpoint},
                {
                    "$push": {
                        "alerts": {"$each": alerts}  # Append each alert to the existing alerts list
                    }
                }
            )
            if result.matched_count > 0:
                print(f"Updated existing document for path: {endpoint}")
            else:
                print(f"Inserted new document for path: {endpoint}")
            
        client.close()
        print("Scan results saved to MongoDB.")

    except Exception as e:
        print(f"Error saving scan results to MongoDB: {str(e)}")
