from flask import render_template, request, redirect, url_for, session, flash, jsonify, Blueprint
from pymongo import MongoClient
from datetime import datetime, timedelta
from functools import wraps
import re
import pyotp
from Modules import AES256, Auth, SHA256, Functions

client = MongoClient('mongodb://localhost:27017/')
db = client['SecureConnect']

SiteBP = Blueprint('site', __name__)

def LoggedInSite(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'key' in session and 'username' in session and 'role' in session:
            session_key = session['key']
            username = session['username']
            useragent = request.headers.get('User-Agent')
            ipaddress = request.remote_addr
            user_session = db.SiteSessions.find_one({
                'SessionKey': session_key,
                'UserName': username,
                'UserAgent': useragent,
                'IPAddress': ipaddress,
                'Role': 'Site',
                'ExpirationTime': {'$gt': datetime.utcnow()}
            })
            if user_session:
                return view_func(*args, **kwargs)
            else:
                session.clear()
                flash('Session expired or invalid. Please log in again.', 'error')
                return redirect(url_for('site.LoginSite'))
        else:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('site.LoginSite'))
    return decorated_function

def NotLoggedInSite(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'key' in session and 'username' in session and 'role' in session:
            return redirect(url_for('site.SiteIndex'))
        return view_func(*args, **kwargs)
    return decorated_function

@SiteBP.route('/')
@LoggedInSite
def SiteIndex():
    return "Hi"

@SiteBP.route('/register', methods=['GET', 'POST'])
@NotLoggedInSite
def RegistrationSite():
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
        ExistingUserName = True if db.Sites.find_one({'UserName': username}) else False
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
            return redirect(url_for('site.RegistrationSite'))

        nameE = AES256.Encrypt(name, AES256.DeriveKey(userid, datecreated, "Name"))
        passwordH = SHA256.HashPassword(password, userid)

        Auth.SendVerificationEmail(username, email, Auth.GenerateVerificationCode())
        db.Users.insert_one({'UserID': userid, 'UserName': username, 'Name': nameE, 'Email': email, 'Password': passwordH, 'DateCreated': datecreated})
        return redirect(url_for('site.VerifyAccountSite', username=username))
    
    return render_template('Site/Register.html')

@SiteBP.route('/verifyaccount/<username>', methods=['GET', 'POST'])
@NotLoggedInSite
def VerifyAccountSite(username):
    if request.method == 'POST':
        EnteredVerificationCode = request.form['VerificationCode']
        VerificationAccount = db.UserVerification.find_one({'UserName': username, 'Verified': False})

        if not VerificationAccount:
            flash('Account not Found or it is Already Verified', 'error')
            return redirect(url_for('site.Login', username=username))

        if EnteredVerificationCode == VerificationAccount['VerificationCode']:
            db.UserVerification.update_one({'UserName': username}, {'$set': {'Verified': True}})
            return redirect(url_for('site.Login'))
        else:
            flash('Invalid Code. Please try again.', 'error')
            return redirect(url_for('site.VerifyAccount', username=username))

    return render_template('Site/VerifyAccount.html', username=username)

@SiteBP.route('/login', methods=['GET', 'POST'])
@NotLoggedInSite
def LoginSite():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        if "@" in login:
            user = db.Users.find_one({'Email': login})
        else:
            user = db.Users.find_one({'UserName': login})

        if not user:
            flash('Invalid Username or Password', 'error')
            return redirect(url_for('site.Login'))

        if not Auth.IsUserVerified(user["UserName"]):
            flash('User not verified. Please complete the OTP verification', 'error')
            return redirect(url_for('site.VerifyAccount', username=user["UserName"]))

        if user and SHA256.CheckPassword(password, user["Password"], user["UserID"]):
            if Auth.Is2FAEnabled(user["UserName"]):
                session['2fa_user'] = user["UserName"]
                return redirect(url_for('site.Verify2FA'))
            
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
            
            return redirect(url_for('site.Index'))
        else:
            flash('Invalid Login or password. Please try again', 'error')
    
    return render_template('Site/Login.html')