from flask import Flask

from Blueprints.Users import UserBP
from Blueprints.Site import SiteBP
from Blueprints.API import APIBP

app = Flask(__name__)
app.secret_key = "GS1jv6dDu1hmVzdWySky7Me324VGPE6H4nMeXF3SsXZyEtRnTuh9y83tzQcQeC72"

app.register_blueprint(UserBP, url_prefix='/')
app.register_blueprint(SiteBP, url_prefix='/sites')
app.register_blueprint(APIBP, url_prefix='/api')

if __name__ == '__main__':
    app.run(debug=True)