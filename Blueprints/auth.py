from flask import Blueprint, redirect, request, url_for, session, flash, render_template, jsonify
import json
from db import mongo
from functools import wraps
from datetime import datetime, timezone
from Modules import AES256
import ast

AuthBP = Blueprint('auth', __name__)

def LoggedInUser(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'key' in session and 'username' in session and 'role' not in session:
            session_key = session['key']
            username = session['username']
            useragent = request.headers.get('User-Agent')
            ipaddress = request.remote_addr
            user_session = mongo.db.UserSessions.find_one({
                'SessionKey': session_key,
                'UserName': username,
                'UserAgent': useragent,
                'IPAddress': ipaddress,
                'ExpirationTime': {'$gt': datetime.now(timezone.utc)}
            })
            if user_session:
                return view_func(*args, **kwargs)
            else:
                session.clear()
                flash('Session expired or invalid. Please log in again.', 'error')
                return redirect(url_for('users.Login', next=request.url))
        else:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('users.Login', next=request.url))
    return decorated_function

def NotLoggedInUser(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'key' in session and 'username' in session and 'role' not in session:
            return redirect(url_for('users.Index'))
        return view_func(*args, **kwargs)
    return decorated_function

def CapitalizeText(Text):
    return Text[0].upper() + Text[1:] if Text else Text

@AuthBP.route('/<string:SiteID>')
@LoggedInUser
def AuthFi(SiteID):
    ReturnURL = request.args.get('ReturnURL')

    UserName = session['username']
    Site = mongo.db.Sites.find_one({'SiteID': SiteID})
    User = mongo.db.Users.find_one({'UserName': UserName})
    UserID = User["UserID"]

    if not Site:
        return render_template("Auth/NotFound.html")

    UserPermissions = None if not (UserPermissions := mongo.db.UserPermissions.find_one({'UserID': UserID})["SitePermissions"]) else UserPermissions.get(SiteID)
    SitePermissions = Site["SitePermissions"]
    MandatoryPermissions = Site["MandatoryPermissions"]

    UserData = {'UserName': User["UserName"], 'Name': CapitalizeText(AES256.Decrypt(User["Name"], AES256.DeriveKey(User["UserID"], User["DateCreated"], "Name")))}
    SiteData = {'SiteName': CapitalizeText(Site["SiteName"]), 'SiteURL': Site["SiteURL"].strip("https://")}

    IsAllPermissionsAvailable = isinstance(MandatoryPermissions, list) and isinstance(UserPermissions, list) and set(MandatoryPermissions).issubset(set(UserPermissions))

    if not UserPermissions or not IsAllPermissionsAvailable:
        ToggleData = []
        for i, label in enumerate(SitePermissions, start=1):
            is_mandatory = "Mandatory" if label in MandatoryPermissions else "Optional" 
            is_checked = "true" if UserPermissions and label in UserPermissions else "false"

            data = {
                "id": i,
                "label": label,
                "description": f"Give access to your {label}", # Collect from Site Admin
                "instruction": f"Give access to your {label}",
                "checked": is_checked,
                "status": is_mandatory
            }
            ToggleData.append(data)
        return render_template("Auth/Auth.html", UserData=UserData, SiteData=SiteData, Permissions=json.dumps(ToggleData), ReturnURL=ReturnURL)
    else:
        # return "1"
        return redirect(url_for('auth.SessionCreate', ReturnURL=ReturnURL))

@AuthBP.route('/authorize', methods=['POST'])
@LoggedInUser
def Authorize():
    UserName = session['username']
    User = mongo.db.Users.find_one({'UserName': UserName})
    UserID = User["UserID"]

    data = request.form.to_dict()  
    ReturnURL = request.args.get('ReturnURL')

    if not ReturnURL:
        ReturnURL = data["ReturnURL"]

    UserName = session['username']
    SiteID = data["SiteID"]
    Permissions = data["Permissions"]
    Permissions = ast.literal_eval(Permissions)

    mongo.db.UserPermissions.update_one({'UserID': UserID}, {'$set': {'SitePermissions': {}}}, upsert=True)
    mongo.db.UserPermissions.update_one({'UserID': UserID}, {'$set': {f'SitePermissions.{SiteID}': Permissions}})
    
    # return "1"
    return redirect(url_for('auth.SessionCreate', ReturnURL=ReturnURL))

@AuthBP.route('/session')
@LoggedInUser
def SessionCreate():

    ReturnURL = request.args.get('ReturnURL') 
    print(ReturnURL)
    return f'{ReturnURL}'