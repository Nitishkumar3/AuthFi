from flask import Flask, render_template, request, redirect, url_for, session, flash

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route("/")
# @login_required
def home():
    return f"""
    <a href='http://127.0.0.1:5000/auth/vdZ85E43UA8EQnSY'>Sign in with AuthFi</a>
    """

if __name__ == '__main__':
    app.run(debug=True, port=9000)