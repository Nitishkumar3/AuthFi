from pymongo import MongoClient
import secrets
import string
import pyotp
import qrcode
import base64
from io import BytesIO
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

def PasswordResetMail(username, email, ResetKey):
    subject = "Secure Connect - Password Reset"
    link = "http://localhost:3000/resetkey/" + str(ResetKey)
    body = "Password Reset Code: " + str(ResetKey) + f" {link}"
    if Mail.SendMail(subject, body, email):
        db.PasswordReset.insert_one({'UserName': username, 'ResetKey': ResetKey})

def GenerateSessionKey(length=32):
    SessionKey = secrets.token_hex(length // 2)
    return SessionKey

def Generate2FASecret():
    return pyotp.random_base32()

def Is2FAEnabled(username):
    user = db.Users.find_one({'UserName': username})
    return 'TwoFactorSecret' in user

def GenerateTOTP(secret):
    totp = pyotp.TOTP(secret)
    return totp.now()

def Generate2FAQR(username, secret):
    data = f"otpauth://totp/{username}?secret={secret}&issuer=Secure%20Connect"
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
    qr.add_data(data)
    qr.make(fit=True)
    qr_img = BytesIO()
    qr.make_image().save(qr_img, 'PNG')
    qr_img.seek(0)
    qr_base64 = base64.b64encode(qr_img.getvalue()).decode()
    return qr_base64