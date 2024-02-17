from flask import render_template, request, redirect, url_for, session, flash, jsonify, Blueprint
from pymongo import MongoClient
from datetime import datetime, timedelta
from functools import wraps
import re
import pyotp
from Modules import AES256, Auth, SHA256, Functions

client = MongoClient('mongodb://localhost:27017/')
db = client['SecureConnect']

UserBP = Blueprint('users', __name__)

def LoggedInUser(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'key' in session and 'username' in session and 'role' not in session:
            session_key = session['key']
            username = session['username']
            useragent = request.headers.get('User-Agent')
            ipaddress = request.remote_addr
            user_session = db.UserSessions.find_one({
                'SessionKey': session_key,
                'UserName': username,
                'UserAgent': useragent,
                'IPAddress': ipaddress,
                'ExpirationTime': {'$gt': datetime.utcnow()}
            })
            if user_session:
                return view_func(*args, **kwargs)
            else:
                session.clear()
                flash('Session expired or invalid. Please log in again.', 'error')
                return redirect(url_for('users.Login'))
        else:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('users.Login'))
    return decorated_function

def NotLoggedInUser(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'key' in session and 'username' in session and 'role' not in session:
            return redirect(url_for('users.Index'))
        return view_func(*args, **kwargs)
    return decorated_function

@UserBP.route('/')
@LoggedInUser
def Index():
    return f'Logged in as {session["username"]}! <a href="/logout">Logout</a>'

# Authentication

@UserBP.route('/register', methods=['GET', 'POST'])
@NotLoggedInUser
def Registration():
    if request.method == 'POST':
        datecreated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        name =  request.form['name']
        username = request.form['username']
        email =  request.form['email']
        password = request.form['password']
        userid = AES256.GenerateRandomString()

        while db.Users.find_one({'UserID': userid}):
            userid = AES256.GenerateRandomString()
    
        UserNameCheck = False if re.match(r'^[a-zA-Z0-9_]{4,}$', username) else True
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-+=])[A-Za-z\d!@#$%^&*()-+=]{8,}$', password) else True
        ExistingUserName = True if db.Users.find_one({'UserName': username}) else False
        ExistingEmailID = True if db.Users.find_one({'Email': email}) else False

        if UserNameCheck or PasswordCheck or ExistingUserName or ExistingEmailID:
            ErrorMessages = []
            if UserNameCheck:
                ErrorMessages.append('Invalid username. It should be at least 4 characters and contain only alphabets (lower and upper), numbers, and underscores.')
            if PasswordCheck:
                ErrorMessages.append('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.')
            if ExistingUserName:
                ErrorMessages.append('Username already exists. Please choose a different username.')
            if ExistingEmailID:
                ErrorMessages.append('Email ID already Registered. Try Logging in.')
            flash(ErrorMessages, 'error')
            return redirect(url_for('users.Registration'))

        nameE = AES256.Encrypt(name, AES256.DeriveKey(userid, datecreated, "Name"))
        passwordH = SHA256.HashPassword(password, userid)

        Auth.SendVerificationEmail(username, email, Auth.GenerateVerificationCode())
        db.Users.insert_one({'UserID': userid, 'UserName': username, 'Name': nameE, 'Email': email, 'Password': passwordH, 'DateCreated': datecreated})
        return redirect(url_for('users.VerifyAccount', username=username))
    
    return render_template('Users/Register.html')

@UserBP.route('/verifyaccount/<username>', methods=['GET', 'POST'])
@NotLoggedInUser
def VerifyAccount(username):
    if request.method == 'POST':
        EnteredVerificationCode = request.form['VerificationCode']
        VerificationAccount = db.UserVerification.find_one({'UserName': username, 'Verified': False})

        if not VerificationAccount:
            flash('Account not Found or it is Already Verified', 'error')
            return redirect(url_for('users.Login', username=username))

        if EnteredVerificationCode == VerificationAccount['VerificationCode']:
            db.UserVerification.update_one({'UserName': username}, {'$set': {'Verified': True}})
            return redirect(url_for('users.Login'))
        else:
            flash('Invalid Code. Please try again.', 'error')
            return redirect(url_for('users.VerifyAccount', username=username))

    return render_template('Users/VerifyAccount.html', username=username)

@UserBP.route('/login', methods=['GET', 'POST'])
@NotLoggedInUser
def Login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        if "@" in login:
            user = db.Users.find_one({'Email': login})
        else:
            user = db.Users.find_one({'UserName': login})

        if not user:
            flash('Invalid username or password.', 'error')
            return redirect(url_for('users.Login'))

        if not Auth.IsUserVerified(user["UserName"]):
            flash('User not verified. Please complete the OTP verification.', 'error')
            return redirect(url_for('users.VerifyAccount', username=user["UserName"]))

        if user and SHA256.CheckPassword(password, SHA256.HashPassword(password, user["UserID"]), user["UserID"]):
            if Auth.Is2FAEnabled(user["UserName"]):
                session['2fa_user'] = user["UserName"]
                return redirect(url_for('users.Verify2FA'))
            
            sessionkey = Auth.GenerateSessionKey()
            useragent = request.headers.get('User-Agent')
            ipaddress = request.remote_addr
            
            currenttime = datetime.utcnow()
            db.UserSessions.insert_one({
                'SessionKey': sessionkey,
                'UserName': user["UserName"],
                'UserAgent': useragent,
                'IPAddress': ipaddress,
                'CreatedAt': currenttime,
                'ExpirationTime': currenttime + timedelta(hours=6)
            })
            db.UserSessions.create_index('ExpirationTime', expireAfterSeconds=0)

            session['key'] = sessionkey
            session['username'] = user["UserName"]
            
            return redirect(url_for('users.Index'))
        else:
            flash('Invalid Login or password. Please try again.', 'error')
    
    return render_template('Users/Login.html')

@UserBP.route('/verify2fa', methods=['GET', 'POST'])
@NotLoggedInUser
def Verify2FA():
    if '2fa_user' not in session:
        return redirect(url_for('users.Login'))

    username = session['2fa_user']
    user = db.Users.find_one({'UserName': username})

    if request.method == 'POST':
        entered_otp = request.form['otp']
        totp_secret = user.get('TwoFactorSecret', '')

        if not totp_secret:
            flash('2FA not enabled for this user.', 'error')
            return redirect(url_for('users.Login'))

        totp = pyotp.TOTP(totp_secret)

        if totp.verify(entered_otp):
            sessionkey = Auth.GenerateSessionKey()
            useragent = request.headers.get('User-Agent')
            ipaddress = request.remote_addr

            currenttime = datetime.utcnow()
            db.UserSessions.insert_one({
                'SessionKey': sessionkey,
                'UserName': user["UserName"],
                'UserAgent': useragent,
                'IPAddress': ipaddress,
                'CreatedAt': currenttime,
                'ExpirationTime': currenttime + timedelta(hours=6)
            })
            db.UserSessions.create_index('ExpirationTime', expireAfterSeconds=0)

            session['key'] = sessionkey
            session['username'] = user["UserName"]
            session.pop('2fa_user')

            return redirect(url_for('users.Index'))
        else:
            flash('Invalid OTP. Please try again.', 'error')

    return render_template('Users/Verify2FA.html', username=username)

@UserBP.route('/forgotpassword', methods=['GET', 'POST'])
@NotLoggedInUser
def ForgotPassword():
    if request.method == 'POST':
        login = request.form['login']

        if "@" in login:
            user = db.Users.find_one({'Email': login})
        else:
            user = db.Users.find_one({'UserName': login})

        if not user:
            flash('Invalid Username or Email ID', 'error')
            return redirect(url_for('users.ForgotPassword'))

        ResetKey = AES256.GenerateRandomString(32)
        Auth.PasswordResetMail(user["UserName"], user["Email"], ResetKey)
        print(user["UserName"], user["Email"], ResetKey)
        flash('A password reset link has been sent to your email. Please check your inbox and follow the instructions.', 'info')
    return render_template('Users/ForgotPassword.html')

@UserBP.route('/resetkey/<ResetKey>', methods=['GET', 'POST'])
@NotLoggedInUser
def ResetPassword(ResetKey):
    if request.method == 'POST':
        NewPassword = request.form['newpassword']
               
        ResetData = db.PasswordReset.find_one({'ResetKey': ResetKey})

        if not ResetData:
            flash('Invalid or Expired reset link. Please initiate the password reset process again.', 'error')
        
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-+=])[A-Za-z\d!@#$%^&*()-+=]{8,}$', NewPassword) else True

        if PasswordCheck:
            flash('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.', 'error')
            return redirect(url_for('users.ResetPassword', ResetKey=ResetKey))
        
        user = db.Users.find_one({'UserName': ResetData['UserName']})

        passwordH = SHA256.HashPassword(NewPassword, user["UserID"])

        db.Users.update_one({'UserName': ResetData['UserName']}, {'$set': {'Password': passwordH}})

        db.PasswordReset.delete_one({'ResetKey': ResetKey})

        return redirect(url_for('users.Login'))
    return render_template('Users/ResetPassword.html', ResetKey=ResetKey)

@UserBP.route('/logout')
@LoggedInUser
def Logout():
    session_key = session['key']
    username = session['username']
    UserSessionDelete = db.UserSessions.delete_one({
        'SessionKey': session_key,
        'UserName': username
    })
    session.clear()
    return redirect(url_for('users.Index'))

# 2FA

@UserBP.route('/2fa', methods=['GET', 'POST'])
@LoggedInUser
def Toggle2FA():
    username = session['username']
    user = db.Users.find_one({'UserName': username})

    QRImage = ""
    if user.get('TwoFactorEnabled', False):
        QRImage = Auth.Generate2FAQR(user["UserName"], user["TwoFactorSecret"])

    if request.method == 'POST':
        if user and user.get('TwoFactorEnabled', False):
            db.Users.update_one({'UserName': username}, {'$unset': {'TwoFactorEnabled': '', 'TwoFactorSecret': ''}})
            flash('Two-factor authentication has been disabled for your account.', 'success')
        else:
            user_secret = Auth.Generate2FASecret()
            db.Users.update_one({'UserName': username}, {'$set': {'TwoFactorEnabled': True, 'TwoFactorSecret': user_secret}})
            flash('Two-factor authentication has been enabled for your account.', 'success')
            
        return redirect(url_for('users.Toggle2FA'))
    return render_template('Users/2FA.html', user=user, QRImage=QRImage)

@UserBP.route('/onboarding', methods=['GET','POST'])
@LoggedInUser
def Onboarding():
    if request.method == 'POST':
        username = session['username']
        user = db.Users.find_one({'UserName': username})
    
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        gender = request.form['gender']
        dob = request.form['dob']
        country = request.form['country']

        EncryptedName = AES256.Encrypt(name, AES256.DeriveKey(user["UserID"], user["DateCreated"], "Name"))
        Email = email
        EncryptedPhone = AES256.Encrypt(phone, AES256.DeriveKey(user["UserID"], user["DateCreated"], "Phone"))
        EncryptedGender = AES256.Encrypt(gender, AES256.DeriveKey(user["UserID"], user["DateCreated"], "Gender"))
        EncryptedDOB = AES256.Encrypt(dob, AES256.DeriveKey(user["UserID"], user["DateCreated"], "DOB"))
        EncryptedCountry = AES256.Encrypt(country, AES256.DeriveKey(user["UserID"], user["DateCreated"], "Country"))

        db.Users.update_one({'UserName': username}, {'$set': {
            'Name': EncryptedName,
            'Email': Email,
            'Phone': EncryptedPhone,
            'Gender': EncryptedGender,
            'DOB': EncryptedDOB,
            'Country': EncryptedCountry,
        }})
        
    username = session['username']
    user = db.Users.find_one({'UserName': username})

    decrypted_data = {}

    if "Name" in user: 
        decrypted_data["Name"] = AES256.Decrypt(user["Name"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Name"))
    if "Email" in user: 
        decrypted_data["Email"] = user["Email"]
    if "Phone" in user: 
        decrypted_data["Phone"] = AES256.Decrypt(user["Phone"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Phone"))
    if "Gender" in user: 
        decrypted_data["Gender"] = AES256.Decrypt(user["Gender"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Gender"))
    if "DOB" in user: 
        decrypted_data["DOB"] = AES256.Decrypt(user["DOB"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "DOB"))
    if "Country" in user: 
        decrypted_data["Country"] = AES256.Decrypt(user["Country"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Country"))

    return render_template('Users/UserOnboarding.html', DecryptedData=decrypted_data)

@UserBP.route('/profile', methods=['GET'])
@LoggedInUser
def Profile():
    username = session['username']
    user = db.Users.find_one({'UserName': username})

    keys = Functions.GetDocumentKeys(username, db)

    if user:
        DecryptedData = {
            'UserName': user["UserName"],
            'Name': AES256.Decrypt(user["Name"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Name")),
            'Email': user["Email"]
        }
        return render_template('Users/Profile.html', DecryptedData=DecryptedData)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('users.Login'))

@UserBP.route('/profile/edit', methods=['GET', 'POST'])
@LoggedInUser
def EditProfile():
    if request.method == 'POST':
        username = session['username']
        user = db.Users.find_one({'UserName': username})

        NewName = request.form['name']

        NewNameE = AES256.Encrypt(NewName, AES256.DeriveKey(user["UserID"], user["DateCreated"], "Name"))

        db.Users.update_one({'UserName': username}, {'$set': {'Name': NewNameE}})
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('users.Profile'))

    username = session['username']
    user = db.Users.find_one({'UserName': username})

    DecryptedData = {
        'Name': AES256.Decrypt(user["Name"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Name")),
        'UserName': user["UserName"],
        'Email': user["Email"]
    }

    return render_template('Users/EditProfile.html', DecryptedData=DecryptedData)