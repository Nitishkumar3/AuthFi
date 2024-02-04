from pymongo import MongoClient
import secrets
import string
from Modules import Mail

client = MongoClient('mongodb://localhost:27017/')
db = client['SecureConnect']

def GenerateVerificationCode(length=32):
    characters = string.ascii_letters + string.digits
    VerificationCode = ''.join(secrets.choice(characters) for _ in range(length))
    return VerificationCode

def SendVerificationEmail(username, email, VerificationCode):
    subject = "Secure Connect - Verify your Account"
    body = "Verification Code: " + str(VerificationCode)
    if Mail.SendMail(subject, body, email):
        db.UserVerification.insert_one({'UserName': username, 'VerificationCode': VerificationCode, 'Verified': False})

def IsUserVerified(username):
    VerifiedStatus = db.UserVerification.find_one({'UserName': username, 'Verified': True})
    return VerifiedStatus is not None