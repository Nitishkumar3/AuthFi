import requests

APIEndpoint = 'http://localhost:3000/endpoint'

APIKey = 'PYeMYwBU1cykECrqhZ0HyD7EpBKhqkM6'
APISecret = 'dKD23Skxr6xxzt0BCNsum9xbkfeLrViX'
UserID = '3G1WHBp4BxuRhqk0'
Data = {"Email": 1, "UserName": 1, "Name": 1}

try:
    response = requests.post(APIEndpoint, json={'APIKey': APIKey, 'APISecret': APISecret, 'UserID': UserID, 'Data': Data})
    print(response.json())

except Exception as e:
    print(f"An error occurred: {e}")