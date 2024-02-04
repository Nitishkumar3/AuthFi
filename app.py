# pip install flask pymongo

from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
import re
from datetime import datetime, timedelta
from functools import wraps
import pyotp
from Modules import Auth, AES256

app = Flask(__name__)
app.secret_key = "GS1jv6dDu1hmVzdWySky7Me324VGPE6H4nMeXF3SsXZyEtRnTuh9y83tzQcQeC72"

client = MongoClient('mongodb://localhost:27017/')
db = client['SecureConnect']

def LoggedIn(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'key' in session and 'username' in session:
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
                return redirect(url_for('Login'))
        else:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('Login'))
    return decorated_function

def NotLoggedIn(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'key' in session and 'username' in session:
            return redirect(url_for('Index'))
        return view_func(*args, **kwargs)
    return decorated_function

@app.route('/')
@LoggedIn
def Index():
    return f'Logged in as {session["username"]}! <a href="/logout">Logout</a>'

@app.route('/register', methods=['GET', 'POST'])
@NotLoggedIn
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
            return redirect(url_for('Registration'))

        nameE = AES256.Encrypt(name, AES256.DeriveKey(userid, datecreated, "Name"))
        passwordE = AES256.Encrypt(password, AES256.DeriveKey(userid, datecreated, "Password"))

        Auth.SendVerificationEmail(username, email, Auth.GenerateVerificationCode())
        db.Users.insert_one({'UserID': userid, 'UserName': username, 'Name': nameE, 'Email': email, 'Password': passwordE, 'DateCreated': datecreated})
        return redirect(url_for('VerifyAccount', username=username))
    
    return render_template('Register.html')

@app.route('/verifyaccount/<username>', methods=['GET', 'POST'])
@NotLoggedIn
def VerifyAccount(username):
    if request.method == 'POST':
        EnteredVerificationCode = request.form['VerificationCode']
        VerificationAccount = db.UserVerification.find_one({'UserName': username, 'Verified': False})

        if not VerificationAccount:
            flash('Account not Found or it is Already Verified', 'error')
            return redirect(url_for('login', username=username))

        if EnteredVerificationCode == VerificationAccount['VerificationCode']:
            db.UserVerification.update_one({'UserName': username}, {'$set': {'Verified': True}})
            return redirect(url_for('Login'))
        else:
            flash('Invalid Code. Please try again.', 'error')
            return redirect(url_for('VerifyAccount', username=username))

    return render_template('VerifyAccount.html', username=username)

@app.route('/login', methods=['GET', 'POST'])
@NotLoggedIn
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
            return redirect(url_for('Login'))

        if not Auth.IsUserVerified(user["UserName"]):
            flash('User not verified. Please complete the OTP verification.', 'error')
            return redirect(url_for('VerifyAccount', username=user["UserName"]))

        if user and password == AES256.Decrypt(user["Password"], AES256.DeriveKey(user["UserID"], user["DateCreated"], "Password")):
            if Auth.Is2FAEnabled(user["UserName"]):
                session['2fa_user'] = user["UserName"]
                return redirect(url_for('Verify2FA'))
            
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
            
            return redirect(url_for('Index'))
        else:
            flash('Invalid Login or password. Please try again.', 'error')
    
    return render_template('Login.html')

@app.route('/verify2fa', methods=['GET', 'POST'])
@NotLoggedIn
def Verify2FA():
    if '2fa_user' not in session:
        return redirect(url_for('Login'))

    username = session['2fa_user']
    user = db.Users.find_one({'UserName': username})

    if request.method == 'POST':
        entered_otp = request.form['otp']
        totp_secret = user.get('TwoFactorSecret', '')

        if not totp_secret:
            flash('2FA not enabled for this user.', 'error')
            return redirect(url_for('Login'))

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

            return redirect(url_for('Index'))
        else:
            flash('Invalid OTP. Please try again.', 'error')

    return render_template('verify2fa.html', username=username)

@app.route('/forgotpassword', methods=['GET', 'POST'])
@NotLoggedIn
def ForgotPassword():
    if request.method == 'POST':
        login = request.form['login']

        if "@" in login:
            user = db.Users.find_one({'Email': login})
        else:
            user = db.Users.find_one({'UserName': login})

        if not user:
            flash('Invalid Username or Email ID', 'error')
            return redirect(url_for('ForgotPassword'))

        ResetKey = AES256.GenerateRandomString(32)
        Auth.PasswordResetMail(user["UserName"], user["Email"], ResetKey)
        print(user["UserName"], user["Email"], ResetKey)
        flash('A password reset link has been sent to your email. Please check your inbox and follow the instructions.', 'info')
    return render_template('ForgotPassword.html')

@app.route('/resetkey/<ResetKey>', methods=['GET', 'POST'])
@NotLoggedIn
def ResetPassword(ResetKey):
    if request.method == 'POST':
        NewPassword = request.form['newpassword']
               
        ResetData = db.PasswordReset.find_one({'ResetKey': ResetKey})

        if not ResetData:
            flash('Invalid or Expired reset link. Please initiate the password reset process again.', 'error')
        
        PasswordCheck = False if re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()-+=])[A-Za-z\d!@#$%^&*()-+=]{8,}$', NewPassword) else True

        if PasswordCheck:
            flash('Invalid password. It should be at least 8 characters and contain at least one lowercase letter, one uppercase letter, one special character, and one number.', 'error')
            return redirect(url_for('ResetPassword', ResetKey=ResetKey))
        
        user = db.Users.find_one({'UserName': ResetData['UserName']})
        
        passwordE = AES256.Encrypt(NewPassword, AES256.DeriveKey(user["UserID"], user["DateCreated"], "Password"))
        db.Users.update_one({'UserName': ResetData['UserName']}, {'$set': {'Password': passwordE}})

        db.PasswordReset.delete_one({'ResetKey': ResetKey})

        flash('Password reset successful. You can now log in with your new password.', 'success')
    return render_template('ResetPassword.html', ResetKey=ResetKey)

@app.route('/logout')
@LoggedIn
def logout():
    session_key = session['key']
    username = session['username']
    UserSessionDelete = db.UserSessions.delete_one({
        'SessionKey': session_key,
        'UserName': username
    })
    session.clear()
    return redirect(url_for('Index'))

@app.route('/2fa', methods=['GET', 'POST'])
@LoggedIn
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
            
        return redirect(url_for('Toggle2FA'))
    return render_template('2FA.html', user=user, QRImage=QRImage)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)