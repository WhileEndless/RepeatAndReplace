# Repeat And Replace - Session Update

This readme.md file explains a simple Flask application that can be used as an example of the Repeat And Replace extension, along with its related configuration file. This example represents a session management scenario and provides detailed explanations on how to configure, operate, and use the extension.

## Flask Application

Firstly, let's examine how the Flask application works. This application provides an example of session management and has the following main functions:

- User authentication with a username and password.
- Logging in and maintaining the session.
- Logging out.

The logic of the application is straightforward. The application resides in a Python file named `app.py`. Here is the basic structure of the application:

```python
from flask import Flask, request, session, jsonify
from datetime import timedelta

app = Flask(__name__)

app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=10)

# User login for session management
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    # User authentication can be performed here
    if username == 'user' and password == 'password':
        session['logged_in'] = True
        return jsonify(message='Successfully logged in.'), 200
    else:
        return jsonify(message='Incorrect username or password.'), 401

# Access to protected data with session protection
@app.route('/protected', methods=['GET'])
def protected():
    if 'logged_in' in session and session['logged_in']:
        return jsonify(message='You can access this private data.'), 200
    else:
        return jsonify(message='You need to log in.'), 401

# Logging out
@app.route('/logout', methods=['GET'])
def logout():
    session['logged_in'] = False
    return jsonify(message='Your session has been terminated.'), 200

if __name__ == '__main__':
    app.run(debug=True)
```

This Flask application performs user login at the `/login` endpoint, allows access to protected data at the `/protected` endpoint with session protection, and terminates the session at the `/logout` endpoint.

## Creating a Config File

You can use the Repeat And Replace extension to test this Flask application by following the steps below. Here's how to create a config file step by step:

1. **Creating the Skeleton of the Config File**

   First, create the general structure of the config file. This structure includes the basic sections of the file:

   ```yaml
   name: session-update

   matcher:
     request:
       - - from: request_header
           contains:
             - "GET /protected HTTP/1.1"
     response:
       - - from: response_header
           contains:
            - "HTTP/1.1 401 UNAUTHORIZED"

   from:
     - Repeater

   repeat:
     - raw_request:
       - |
         POST /login HTTP/1.1
         Host: 127.0.0.1:5000
         # Other HTTP headers...
         {"username":"user","password":"password"}

       service:
         protocol: http
         port: 5000
         host: 127.0.0.1
   ```

   This structure includes the basic sections of the config file. In the "name" section, specify the name of the file, in the "matcher" section, define the conditions for when requests will match, in the "from" section, specify which Burp Suite modules will monitor the traffic, and in the "repeat" section, specify how a request will be repeated.

2. **Defining the Matcher Section**

   The matcher section defines conditions for when the extension will come into play. For example, we use these conditions when we want to automatically create a new session when the session expires:

   ```yaml
   matcher:
     request:
       - - from: request_header
           contains:
             - "GET /protected HTTP/1.1"
     response:
       - - from: response_header
           contains:
            - "HTTP/1.1 401 UNAUTHORIZED"
   ```

   In this example, we specify that the extension will come into play when the request is `GET /protected` and the response is `HTTP/1.1 401 UNAUTHORIZED`.

3. **Defining the Module Source**

   In the `from` section, specify which Burp Suite modules the extension will monitor. In this example, we use the "Repeater" module:

   ```yaml
   from:
     - Repeater
   ```

   This indicates that the extension will only process requests coming from the Repeater module.

4. **Repeating Requests**

   The `repeat` section defines how a request will be repeated. Requests can be duplicated using the "Repeat And Replace" feature within Burp Suite. In the example, we use the following structure to repeat the login request:

   ```yaml
   repeat:
     - raw_request:
       - |
         POST /login HTTP/1.1
         Host: 127.0.0.1:5000
         # Other HTTP headers...
         {"username":"user","password":"password"}

       service:
         protocol: http
         port: 5000
         host: 127.0.0.1
   ```

   In this section, we specify the raw_request that generates the login request and configure the target service.

5. **Extracting and Replacing Information**

   The extension can be used to modify the content of requests and responses. In the example, we use the following structure to extract and reuse session information:

   ```yaml
   extractor:
     - name: session
       start: "Set-Cookie: session="
       end: ";"
       regex: false

   replacer:
     - replace_with: session
       start: "Cookie: session="
       end: ";"
       regex: false
   ```

   In this section, we define an extractor to extract session information and a replacer to reuse the extracted session information.

6. **Continuous Update**

   If the `continuousupdate` value is set to `true`, the extension will repeat the requests and monitor the responses each time a request matches. A new session will be created when a specified error is encountered or when the session expires. This allows the same session to be reused for a period (until the session expires). This feature is useful for scenarios that require continuous updates.

   ```yaml
   continuousupdate: true
   ```

By following these steps, you can create a config file to test your Flask application using the Repeat And Replace extension. You can customize the config file for more complex scenarios.
