# Repeat And Replace - Standard Repeat Scenario

This document provides a detailed explanation of a Flask application and its associated configuration file for the Repeat And Replace extension. The Flask application includes a series of API endpoints and facilitates a token-based flow between these endpoints.

## Flask Application and Operation Logic

The application is located in a Python file named `app.py` and includes a set of endpoints:

- **`/test1` Endpoint:** Accepts a GET request and generates random tokens for `test2` and `deger`.
- **`/test2` Endpoint:** Accepts a POST request, verifies incoming tokens, and generates a new token for `test3`.
- **`/test3`, `/test4`, `/test5` Endpoints:** Similarly, they accept a POST request, verify incoming tokens, and generate a new token for the next endpoint.

This chained flow demonstrates how to handle token-based requests and token validations.

## Creating the Config File

### 1. Creating the Skeleton of the Config File

To begin with, let's create a config file named `standard-repeat.yaml`:

```yaml
name: "standard repeat"

matcher: []

from: []

repeat: []

extractor: []

replacer: []

continuousupdate: false
```

### 2. Defining the Matcher Section

The matcher section defines the conditions under which the extension will come into play. Here, we are focusing on the `POST /test5` request because it represents the final step of the five-step request chain we observe during pentesting:

```yaml
matcher:
  - - from: request_header
      contains:
        - POST /test5
```

### 3. Specifying Module Sources

The `from` section determines which Burp Suite modules the extension will monitor requests from. In this example, "Repeater," "Scanner," and "Intruder" modules are selected:

```yaml
from:
  - Repeater
  - Scanner
  - Intruder
```

### 4. Repeating Requests

In the `repeat` section, requests required for the first two steps are defined. This specifies how the chaining process will occur:

```yaml
repeat:
  # Step 1: Send a GET request to the /test1 endpoint
  - service:
      host: "localhost"
      port: 5000
      protocol: http
    raw_request:
      - |
        GET /test1 HTTP/1.1
        Host: 127.0.0.1:5000
        # Other HTTP headers...
    extractor:
      - name: token2
        start: "\"token\": \""
        end: "\""
        regex: false
      - name: deger
        start: "\"deger\": \""
        end: "\""
        regex: false

  # Step 2: Send a POST request to the /test2 endpoint
  - service:
      host: "localhost"
      port: 5000
      protocol: http
    raw_request:
      - |
        POST /test2?token={{token2}} HTTP/1.1
        Host: 127.0.0.1:5000
        Content-Type: application/json
        # Other HTTP headers...
        {"deger":"{{deger}}"}
```

### 5. Subsequent Steps and Continuous Update

Similar extractor and replacer definitions can be made for subsequent steps. Each step creates new requests using information obtained from the previous step. The `continuousupdate` value is set to `false` in this scenario, indicating that there will be no continuous updates.

By following these steps, you can create a Flask application and configuration file for the Repeat And Replace extension and customize this example to meet your specific needs. This example provides a detailed demonstration of the extension's chaining and conditional request processing capabilities.
