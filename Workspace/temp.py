import pymongo

client = pymongo.MongoClient("mongodb://localhost:27017/")
database = client["SecureConnect"]
collection = database["UserPermissions"]

data_to_store = { 
    "UserID": "eOEaG4hYJZAaq6JR",
    "SitePermissions": {"SITEID1":["Name","Email"], "SITEID2":["Name"]},
    "Sites": {"SITEID1": "name1", "SITEID2": "name2"}
}

collection.insert_one(data_to_store)
client.close()