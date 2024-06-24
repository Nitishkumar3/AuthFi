from flask import render_template, request, redirect, url_for, session, flash, jsonify, Blueprint
from datetime import datetime, timedelta, timezone
from functools import wraps
import re
from Modules import AES256, Auth, SHA256, Functions, SiteCheck
from db import mongo

SiteBP = Blueprint('site', __name__)

def LoggedInSite(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'SessionKeySite' in session and 'UserNameSite' in session:
            session_key = session['SessionKeySite']
            username = session['UserNameSite']
            useragent = request.headers.get('User-Agent')
            ipaddress = request.remote_addr
            user_session = mongo.db.SiteUserSessions.find_one({
                'SessionKey': session_key,
                'UserName': username,
                'UserAgent': useragent,
                'IPAddress': ipaddress,
                'Role': 'Site',
                'ExpirationTime': {'$gt': datetime.now(timezone.utc)}
            })

            if user_session:
                return view_func(*args, **kwargs)
            else:
                session.clear()
                flash('Session expired or invalid. Please log in again.', 'error')
                return redirect(url_for('site.Login'))
        else:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('site.Login'))
    return decorated_function

def NotLoggedInSite(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'SessionKeySite' in session and 'UserNameSite' in session:
            return redirect(url_for('site.Index'))
        return view_func(*args, **kwargs)
    return decorated_function

@SiteBP.route('/')
@LoggedInSite
def Index():
    UserName = session['UserNameSite']
    User = mongo.db.SiteUsers.find_one({'UserName': UserName})
    UserID = User["UserID"]
    Sites = list(mongo.db.Sites.find({'UserID': UserID}))

    SitesData={}
    for i in Sites:
        SitesData[i["SiteName"]] = i["SiteID"]

    print(UserName)
    print(UserID)
    print(SitesData)
    
    return render_template('Site/Dashboard.html', UserName = UserName, SitesData = SitesData)

@SiteBP.route('/register', methods=['GET', 'POST'])
@NotLoggedInSite
def Registration():
    if request.method == 'POST':
        datecreated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        name =  request.form['name']
        username = request.form['username']
        email =  request.form['email']
        password = request.form['password']
        Organization = request.form['organization']
        Phone = request.form['phone']

        UserID = AES256.GenerateRandomString()

        while mongo.db.SiteUsers.find_one({'UserID': UserID}):
            UserID = AES256.GenerateRandomString()
    
        UserNameCheck = False if re.match(r'^[a-zA-Z0-9_]{4,}$', username) else True
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-+=])[A-Za-z\d!@#$%^&*()-+=]{8,}$', password) else True
        ExistingUserName = True if mongo.db.SiteUsers.find_one({'UserName': username}) else False
        ExistingEmailID = True if mongo.db.SiteUsers.find_one({'Email': email}) else False

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
            return redirect(url_for('site.Registration'))

        nameE = AES256.Encrypt(name, AES256.DeriveKey(UserID, datecreated, "Name"))
        passwordH = SHA256.HashPassword(password, UserID)
        PhoneE = AES256.Encrypt(Phone, AES256.DeriveKey(UserID, datecreated, "Phone"))
        OrganizationE = AES256.Encrypt(Organization, AES256.DeriveKey(UserID, datecreated, "Organization"))
    
        Auth.SendVerificationEmail(username, email, Auth.GenerateVerificationCode())
        mongo.db.SiteUsers.insert_one({'UserID': UserID, 'UserName': username, 'Name': nameE, 'Email': email, 'Phone': PhoneE, 'Organization': OrganizationE, 'Password': passwordH, 'DateCreated': datecreated})
        return redirect(url_for('site.VerifyAccount', username=username))
    
    return render_template('Site/Register.html')

@SiteBP.route('/verifyaccount/<username>', methods=['GET', 'POST'])
@NotLoggedInSite
def VerifyAccount(username):
    if request.method == 'POST':
        EnteredVerificationCode = request.form['VerificationCode']
        VerificationAccount = mongo.db.UserVerification.find_one({'UserName': username, 'Verified': False})

        if not VerificationAccount:
            flash('Account not Found or it is Already Verified', 'error')
            return redirect(url_for('site.Login', username=username))

        if EnteredVerificationCode == VerificationAccount['VerificationCode']:
            mongo.db.UserVerification.update_one({'UserName': username}, {'$set': {'Verified': True}})
            return redirect(url_for('site.Login'))
        else:
            flash('Invalid Code. Please try again.', 'error')
            return redirect(url_for('site.VerifyAccount', username=username))

    return render_template('Site/VerifyAccount.html', username=username)

@SiteBP.route('/login', methods=['GET', 'POST'])
@NotLoggedInSite
def Login():
    if request.method == 'POST':
        login = request.form['login']
        password = request.form['password']

        if "@" in login:
            user = mongo.db.SiteUsers.find_one({'Email': login})
        else:
            user = mongo.db.SiteUsers.find_one({'UserName': login})

        if not user:
            flash('Invalid Username or Password', 'error')
            return redirect(url_for('site.Login'))

        if not Auth.IsUserVerified(user["UserName"]):
            flash('User not verified. Please complete the OTP verification', 'error')
            return redirect(url_for('site.VerifyAccount', username=user["UserName"]))
        
        if user and SHA256.CheckPassword(password, user["Password"], user["UserID"]):
            # if Auth.Is2FAEnabled(user["UserName"]):
            #     session['2fa_user'] = user["UserName"]
            #     return redirect(url_for('site.Verify2FA'))
            
            sessionkey = Auth.GenerateSessionKey()
            useragent = request.headers.get('User-Agent')
            ipaddress = request.remote_addr
            
            currenttime = datetime.now(timezone.utc)
            mongo.db.SiteUserSessions.insert_one({
                'SessionKey': sessionkey,
                'UserName': user["UserName"],
                'UserAgent': useragent,
                'IPAddress': ipaddress,
                'CreatedAt': currenttime,
                'Role': 'Site',
                'ExpirationTime': currenttime + timedelta(hours=6)
            })
            mongo.db.SiteUserSessions.create_index('ExpirationTime', expireAfterSeconds=0)

            session['SessionKeySite'] = sessionkey
            session['UserNameSite'] = user["UserName"]
            return redirect(url_for('site.Index'))
        else:
            flash('Invalid Login or password. Please try again', 'error')
    
    return render_template('Site/Login.html')


#         if UserNameCheck or PasswordCheck or ExistingUserName or ExistingEmailID:
#             ErrorMessages = []
#             if UserNameCheck:
#                 ErrorMessages.append('Invalid username. It should be at least 4 characters and contain only alphabets (lower and upper), numbers, and underscores.')
#             if PasswordCheck:
#                 ErrorMessages.append('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.')
#             if ExistingUserName:
#                 ErrorMessages.append('Username already exists. Please choose a different username.')
#             if ExistingEmailID:
#                 ErrorMessages.append('Email ID already Registered. Try Logging in.')
#             flash(ErrorMessages, 'error')
#             return redirect(url_for('users.Registration'))

#         nameE = AES256.Encrypt(name, AES256.DeriveKey(userid, datecreated, "Name"))
#         passwordH = SHA256.HashPassword(password, userid)

#         Auth.SendVerificationEmail(username, email, Auth.GenerateVerificationCode())
#         mongo.db.Users.insert_one({'UserID': userid, 'UserName': username, 'Name': nameE, 'Email': email, 'Password': passwordH, 'DateCreated': datecreated})
#         return redirect(url_for('users.VerifyAccount', username=username))

@SiteBP.route('/forgotpassword', methods=['GET', 'POST'])
@NotLoggedInSite
def ForgotPassword():
    if request.method == 'POST':
        login = request.form['login']

        if "@" in login:
            user = mongo.db.SiteUsers.find_one({'Email': login})
        else:
            user = mongo.db.SiteUsers.find_one({'UserName': login})

        if not user:
            flash('Invalid Username or Email ID', 'error')
            return redirect(url_for('site.ForgotPassword'))

        ResetKey = AES256.GenerateRandomString(32)
        Auth.PasswordResetMail(user["UserName"], user["Email"], ResetKey)
        flash('A Password Reset Link has been sent to your Email! Please check your Inbox and Follow the Instructions', 'info')
    return render_template('Site/ForgotPassword.html')


@SiteBP.route('/resetkey/<ResetKey>', methods=['GET', 'POST'])
@NotLoggedInSite
def ResetPassword(ResetKey):
    if request.method == 'POST':
        NewPassword = request.form['password']
            
        ResetData = mongo.db.PasswordReset.find_one({'ResetKey': ResetKey})

        if not ResetData:
            flash('Invalid or Expired reset link. Please initiate the password reset process again.', 'error')
        
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-+=])[A-Za-z\d!@#$%^&*()-+=]{8,}$', NewPassword) else True

        if PasswordCheck:
            flash('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.', 'error')
            return redirect(url_for('site.ResetPassword', ResetKey=ResetKey))
        
        user = mongo.db.SiteUsers.find_one({'UserName': ResetData['UserName']})

        passwordH = SHA256.HashPassword(NewPassword, user["UserID"])

        mongo.db.SiteUsers.update_one({'UserName': ResetData['UserName']}, {'$set': {'Password': passwordH}})

        mongo.db.PasswordReset.delete_one({'ResetKey': ResetKey})
        
        flash('Password reset successful. Try Loggin in.', 'info')

        # return redirect(url_for('users.Login'))
    return render_template('Site/ResetPassword.html', ResetKey=ResetKey)

@SiteBP.route('/addsite', methods=['GET', 'POST'])
@LoggedInSite
def AddSite():
    if request.method == 'POST':
        username = session['UserNameSite']
        User = mongo.db.SiteUsers.find_one({'UserName': username})

        SiteID = AES256.GenerateRandomString()
        SiteName = request.form['sitename']
        SiteSecret = AES256.GenerateRandomString(Length=32)
        UserID = User["UserID"]
        SiteURL = request.form['url']
        CallbackURL = request.form['callbackurl']
        SitePermissions = request.form.getlist('AllPermissions')
        MandatoryPermissions = request.form.getlist('MandatoryPermissions')
        Category = request.form['category']
        Description = request.form['description']
        Verified = False
        DateCreated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        SiteURL = SiteCheck.FormatURL(SiteURL)
        CallbackURL = SiteCheck.FormatURL(CallbackURL)
        
        SiteExistCheck = False if mongo.db.Sites.find_one({"SiteURL": SiteURL}) else True
        SiteUpCheck = SiteCheck.CheckSiteUp(SiteURL)
        SSLCheck = SiteCheck.CheckSSLCertificate(SiteURL)

        # if SiteExistCheck or SiteUpCheck or SSLCheck:
        if not (SiteExistCheck and SiteUpCheck and SSLCheck):
            ErrorMessages = []
            if not SiteExistCheck:
                ErrorMessages.append('Site Already Exists')
            if not SiteUpCheck:
                ErrorMessages.append('Site is Currently Down. Try again Later.')
            if not SSLCheck:
                ErrorMessages.append("Site doesn't have a SSL Certificate")
            flash(ErrorMessages, 'error')
            return redirect(url_for('site.AddSite'))

        if SiteExistCheck and SiteUpCheck and SSLCheck:
            mongo.db.Sites.insert_one({
                "SiteID": SiteID,
                "SiteName": SiteName,
                "SiteSecret": SiteSecret,
                "UserID": UserID,
                "SiteURL": SiteURL,
                "CallbackURL": CallbackURL,
                "SitePermissions": SitePermissions,
                "MandatoryPermissions": MandatoryPermissions,
                "Category": Category,
                "Description": Description,
                "Verified": Verified,
                "DateCreated": DateCreated
            })
        return redirect(url_for('site.VerifySite', SiteID=SiteID))
    return render_template('Site/AddSite.html')

@SiteBP.route('/verifysite/<SiteID>', methods=['GET', 'POST'])
@LoggedInSite
def VerifySite(SiteID):
    UserName = session['UserNameSite']
    if request.method == 'POST':
        UserData = mongo.db.SiteUsers.find_one({'UserName': UserName})
        UserID = UserData["UserID"]
        SiteData = mongo.db.Sites.find_one({'SiteID': SiteID})
        SiteURL = SiteData["SiteURL"]

        if SiteCheck.CheckTXTRecord(SiteURL, SiteID):
            mongo.db.Sites.update_one({'SiteID': SiteID}, {"$set": {"Verified": True}})

        # EnteredVerificationCode = request.form['VerificationCode']
        # VerificationAccount = mongo.db.UserVerification.find_one({'UserName': username, 'Verified': False})

        # if not VerificationAccount:
        #     flash('Account not Found or it is Already Verified', 'error')
        #     return redirect(url_for('site.Login', username=username))

        # if EnteredVerificationCode == VerificationAccount['VerificationCode']:
        #     mongo.db.UserVerification.update_one({'UserName': username}, {'$set': {'Verified': True}})
        #     return redirect(url_for('site.Login'))
        # else:
        #     flash('Invalid Code. Please try again.', 'error')
        #     return redirect(url_for('site.VerifyAccount', username=username))

    return render_template('Site/VerifySite.html', SiteID=SiteID)

@SiteBP.route('/<SiteID>', methods=['GET', 'POST'])
@LoggedInSite
def SiteDashboard(SiteID):
    username = session['UserNameSite']

    print(SiteID)

    if not Functions.IsSiteVerified(SiteID):
        return redirect(url_for('site.VerifySite', SiteID=SiteID))

    return ""

@SiteBP.route('/logout')
@LoggedInSite
def Logout():
    session_key = session['SessionKeySite']
    username = session['UserNameSite']

    UserSessionDelete = mongo.db.SiteUserSessions.delete_one({
        'SessionKey': session_key,
        'UserName': username
    })
    session.clear()
    return redirect(url_for('site.Index'))
