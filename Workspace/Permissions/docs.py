from pymongo import MongoClient

client = MongoClient('mongodb://localhost:27017/')
db = client['SecureConnect']

UserID = "nk"

SiteID = input("Enter the site: ")
Permission = input("Enter the new Perm Type: ")
PermissionValue = input("Enter the new Perm value: ")

document = {
    "UserID": UserID,
    "Sites": {
        SiteID: {
            Permission: PermissionValue
        }
    }
}

result = db.UserPermissions.insert_one(document)

# Operation = {
#     "$set": {
#         f"Sites.{SiteID}.{Permission}": PermissionValue
#     }
# }

# result = db.UserPermissions.update_one({"UserID": UserID}, Operation)

# if result.modified_count > 0:
#     print("Document updated successfully.")
# else:
#     print("No documents matched the filter criteria.")