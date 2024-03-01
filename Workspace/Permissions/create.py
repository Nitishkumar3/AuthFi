from flask import Flask
from flask_pymongo import PyMongo

mongo = PyMongo()
app = Flask(__name__)
app.secret_key = "GS1jv6dDu1hmVzdWySky7Me324VGPE6H4nMeXF3SsXZyEtRnTuh9y83tzQcQeC72"

app.config['MONGO_URI'] = 'mongodb://localhost:27017/SecureConnect'
mongo.init_app(app)

@app.route('/create')
def Create():
    UserID = "eOEaG4hYJZAaq6JR"

    SiteID = "S12340"
    SiteName = "abc"
    Permissions = ["Email", "Name", "Phone"]

    document = {
        "UserID": UserID,
        "SitePermissions": {
            SiteID: Permissions
        },
        "Sites":{
            SiteID : SiteName
        }
    }

    result = mongo.db.UserPermissions.insert_one(document)
    return " "

if __name__ == '__main__':
    app.run(debug=True, port=5000)