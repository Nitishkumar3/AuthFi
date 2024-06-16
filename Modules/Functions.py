from pymongo import MongoClient
from dotenv import load_dotenv
import os

load_dotenv()
MONGO_URI = os.getenv('MONGO_URI')

client = MongoClient(MONGO_URI)
db = client['AuthFi']

def GetDocumentKeys(username, mongo):
    user = mongo.db.Users.find_one({'UserName': username})
    blacklist = ["_id", "UserID", "UserName", "Name", "Email", "Password", "DateCreated", "TwoFactorEnabled", "TwoFactorSecret"]
    if user:
        keys = user.keys()
        if blacklist:
            keys = [key for key in keys if key not in blacklist]
        return list(keys)
    else:
        return []
    
def IsSiteVerified(SiteID):
    SiteData = db.Sites.find_one({'SiteID': SiteID})
    if SiteData["Verified"] == False:
        return False
    else:
        return True