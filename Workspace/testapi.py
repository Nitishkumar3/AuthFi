import requests

def GetData(SiteID, SiteSecret, UserID, Data):
    APIEndpoint = 'http://127.0.0.1:5000/api/endpoint'
    try:
        response = requests.post(APIEndpoint, json={'SiteID': SiteID, 'SiteSecret': SiteSecret, 'UserID': UserID, 'Data': Data})
        return response.json()
    except Exception as e:
        return f"An error occurred: {e}"

SiteID = 'O5Gk0qQ07F0tLrDg'
SiteSecret = '7yji098iErSS0OVkvPV5LLXOyOxHi5gF'

UserID = 'FoZIHuCdK09dGGBZ'
Data = ["UserID", "UserName", "Name", "Email"]

out = GetData(SiteID, SiteSecret, UserID, Data)

print(out)