# pip install flask pymongo

from flask import Flask, render_template, request, redirect, url_for, session, flash
from pymongo import MongoClient
import re
from datetime import datetime

from Modules import Auth, AES256

app = Flask(__name__)
app.secret_key = "GS1jv6dDu1hmVzdWySky7Me324VGPE6H4nMeXF3SsXZyEtRnTuh9y83tzQcQeC72"

client = MongoClient('mongodb://localhost:27017/')
db = client['SecureConnect']

@app.route('/')
def Index():
    if 'username' in session:
        return f'Logged in as {session["username"]}! <a href="/logout">Logout</a>'
    return 'You are not logged in. <a href="/login">Login</a>'

@app.route('/register', methods=['GET', 'POST'])
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
    
    return render_template('register.html')

@app.route('/verifyaccount/<username>', methods=['GET', 'POST'])
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

    return render_template('verifyaccount.html', username=username)

@app.route('/login', methods=['GET', 'POST'])
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
            session['username'] = user["UserName"]
            return redirect(url_for('Index'))
        else:
            flash('Invalid Login or password. Please try again.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('Index'))

if __name__ == '__main__':
    app.run(debug=True, port=3000)