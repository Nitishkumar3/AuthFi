import requests

def GetData(SiteID, SiteSecret, UserID, Data):
    APIEndpoint = 'http://localhost:3000/endpoint'
    try:
        response = requests.post(APIEndpoint, json={'SiteID': SiteID, 'SiteSecret': SiteSecret, 'UserID': UserID, 'Data': Data})
        return response.json()
    except Exception as e:
        return f"An error occurred: {e}"

SiteID = 'rrP5HwAxys0Hq3PoQuezrxEJliP00fOF'
SiteSecret = 'rHkzthBZlOJ6RLPITiYmhisMkWZ1uEbo'
UserID = 'WOkZVqiSSWyfFXGR'
Data = {"UserID": 1, "UserName": 1, "Name": 1, "Email": 1, "Password": 1}

out = GetData(SiteID, SiteSecret, UserID, Data)

print(out)
