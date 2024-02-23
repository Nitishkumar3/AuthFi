from flask import Flask, send_from_directory, render_template
from db import mongo
from Blueprints.users import UserBP
from Blueprints.site import SiteBP
from Blueprints.api import APIBP

app = Flask(__name__)
app.secret_key = "GS1jv6dDu1hmVzdWySky7Me324VGPE6H4nMeXF3SsXZyEtRnTuh9y83tzQcQeC72"

app.config['MONGO_URI'] = 'mongodb://localhost:27017/SecureConnect'
mongo.init_app(app)

app.register_blueprint(UserBP, url_prefix='/', mongo=mongo)
app.register_blueprint(SiteBP, url_prefix='/sites', mongo=mongo)
app.register_blueprint(APIBP, url_prefix='/api', mongo=mongo)

@app.route('/')
def Index():
    return render_template('Index.html')

@app.route('/assets/<path:filename>')
def Static(filename):
    return send_from_directory('Assets', filename)

if __name__ == '__main__':
    app.run(debug=True, port=5000)