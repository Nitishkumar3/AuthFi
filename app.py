from flask import Flask, send_from_directory, render_template, session
from db import mongo
from Blueprints.users import UserBP
from Blueprints.site import SiteBP
from Blueprints.api import APIBP
from Blueprints.auth import AuthBP
from dotenv import load_dotenv
import os
from werkzeug.middleware.proxy_fix import ProxyFix

load_dotenv()
MONGO_URI = os.getenv('MONGO_URI')

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1)
app.secret_key = "GS1jv6dDu1hmVzdWySky7Me324VGPE6H4nMeXF3SsXZyEtRnTuh9y83tzQcQeC72"

app.config['MONGO_URI'] = MONGO_URI
mongo.init_app(app)

app.register_blueprint(UserBP, url_prefix='/', mongo=mongo)
app.register_blueprint(SiteBP, url_prefix='/app', mongo=mongo)
app.register_blueprint(APIBP, url_prefix='/api', mongo=mongo)
app.register_blueprint(AuthBP, url_prefix='/auth', mongo=mongo)

@app.route('/')
def Index():
    if 'key' in session and 'username' in session and 'role' not in session:
        IsLoggedIn = True
    else:
        IsLoggedIn = False
    return render_template('Index.html', IsLoggedIn=IsLoggedIn)

@app.route('/assets/<path:filename>')
def Static(filename):
    return send_from_directory('Assets', filename)

if __name__ == '__main__':
    app.run(debug=True, port=5000, host="0.0.0.0")