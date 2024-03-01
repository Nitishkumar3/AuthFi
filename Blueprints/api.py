from flask import jsonify, request, Blueprint
from Modules import AES256
from db import mongo

APIBP = Blueprint('api', __name__)

@APIBP.route('/')
def api():
    SiteID = AES256.GenerateRandomString(32)
    SiteSecret = AES256.GenerateRandomString(32)
    UserID = "3G1WHBp4BxuRhqk0"
    mongo.db.API.insert_one({'SiteID': SiteID, 'SiteSecret': SiteSecret, 'UserID': UserID})
    return f"API Key: {SiteID} SiteSecret: {SiteSecret}"

@APIBP.route('/endpoint', methods=['POST'])
def api_endpoint():
    try:
        RequestData = request.get_json()

        # IPAddress = request.remote_addr
        # UserAgent = request.user_agent.string
        # print(IPAddress, UserAgent)

        SiteID = RequestData.get('SiteID')
        SiteSecret = RequestData.get('SiteSecret')

        UserID = RequestData.get('UserID')
        GetData = RequestData.get('Data')

        if not SiteID or not SiteSecret:
            return jsonify({'error': 'API key and Secret are required'}), 400
        
        SiteData = mongo.db.Sites.find_one({'SiteID': SiteID, 'SiteSecret': SiteSecret})
        if not SiteData:
            return jsonify({'error': 'Invalid API key or secret'}), 401
                
        UserCheck = mongo.db.SiteUsers.find_one({'SiteID': SiteID})
        if not UserID in UserCheck.get("Users", []):
            return jsonify({'error': 'Invalid user'}), 401

        data = mongo.db.Users.find_one({'UserID': UserID})
        Permissions = mongo.db.UserPermissions.find_one({'UserID': UserID})["SitePermissions"][SiteID]
        Permissions.extend(["UserName","UserID"])

        if not all(item in Permissions for item in GetData):
            return jsonify({'error': 'No Permission'}), 401

        Target = ["UserID", "UserName", "Email"]
        UnEncData = list(set(GetData) & set(Target))
        GetData = [item for item in GetData if item not in UnEncData]

        ReturnData = {}

        for FetchData in UnEncData:
            ReturnData[FetchData] = data[FetchData]

        for FetchData in GetData:
            ReturnData[FetchData] = AES256.Decrypt(data[FetchData], AES256.DeriveKey(data["UserID"], data["DateCreated"], FetchData))

        return jsonify(ReturnData)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500