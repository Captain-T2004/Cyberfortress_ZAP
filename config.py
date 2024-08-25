import os
from dotenv import load_dotenv

load_dotenv()  # This loads the variables from .env

class Config:
    ZAP_API_KEY = os.environ.get('ZAP_API_KEY')
    MONGO_URI = os.environ.get('MONGO_URI')
    MONGO_DB_NAME = os.environ.get('DB_NAME')
    MONGO_COLLECTION_NAME = os.environ.get('COLLECTION_NAME')