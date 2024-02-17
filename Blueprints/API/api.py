from flask import Blueprint, jsonify, request
from Modules import AES256
from pymongo import MongoClient

APIBP = Blueprint('api', __name__)

client = MongoClient('mongodb://localhost:27017/')
db = client['SecureConnect']

@APIBP.route('/')
def api():
    SiteID = AES256.GenerateRandomString(32)
    SiteSecret = AES256.GenerateRandomString(32)
    UserID = "3G1WHBp4BxuRhqk0"
    db.API.insert_one({'SiteID': SiteID, 'SiteSecret': SiteSecret, 'UserID': UserID})
    return f"API Key: {SiteID} SiteSecret: {SiteSecret}"

@APIBP.route('/endpoint', methods=['POST'])
def api_endpoint():
    try:
        ReuestData = request.get_json()

        IPAddress = request.remote_addr
        UserAgent = request.user_agent.string

        #print(IPAddress, UserAgent)

        SiteID = ReuestData.get('SiteID')
        SiteSecret = ReuestData.get('SiteSecret')
        UserID = ReuestData.get('UserID')
        Data = ReuestData.get('Data')

        GetData = list(Data.keys())

        if not SiteID or not SiteSecret:
            return jsonify({'error': 'API key and Secret are required'}), 400
        
        result = db.API.find_one({'SiteID': SiteID, 'SiteSecret': SiteSecret})
        
        if not result:
            return jsonify({'error': 'Invalid API key or secret'}), 401
        
        if result['UserID'] != UserID:
            return jsonify({'error': 'Invalid user'}), 401

        data = db.Users.find_one({'UserID': result['UserID']})

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