from flask import Flask, request, session, jsonify
from datetime import timedelta

app = Flask(__name__)

app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=10)

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    
    if username == 'user' and password == 'password':
        session['logged_in'] = True
        return jsonify(message='Successfully logged in.'), 200
    else:
        return jsonify(message='Incorrect username or password.'), 401


@app.route('/protected', methods=['GET'])
def protected():
    if 'logged_in' in session and session['logged_in']:
        return jsonify(message='You can access this private data.'), 200
    else:
        return jsonify(message='You need to log in.'), 401

@app.route('/logout', methods=['GET'])
def logout():
    session['logged_in'] = False
    return jsonify(message='Your session has been terminated.'), 200

if __name__ == '__main__':
    app.run(debug=True)
