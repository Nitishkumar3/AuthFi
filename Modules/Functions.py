def GetDocumentKeys(username, db):
    user = db.Users.find_one({'UserName': username})
    blacklist = ["_id", "UserID", "UserName", "Name", "Email", "Password", "DateCreated", "TwoFactorEnabled", "TwoFactorSecret"]
    if user:
        keys = user.keys()
        if blacklist:
            keys = [key for key in keys if key not in blacklist]
        return list(keys)
    else:
        return []