# Repeat And Replace

## Overview
Repeat And Replace is a Burp Suite extension that analyzes HTTP requests and responses through pattern matching and modifies and resends content based on specific criteria. It is designed for developers and security researchers with the aim of automating manual workflows, saving time, and reducing the likelihood of errors.

## Features
- **Pattern Matching:** Automatically detects patterns defined in HTTP requests and responses.
- **Processing Requests from Modules:** Processes requests coming from specific Burp Suite modules.
- **Request Repeating:** Repeats HTTP requests in the order specified in the configuration file and according to service settings.
- **Information Extraction and Replacement:** Extracts information from requests or responses and replaces specific text with this information.
- **Automatic and Continuous Updates:** Automatically detects and applies configuration changes in the configuration file.
- **Session Management:** Independent session management and connection isolation.
- **Flow Control:** Ensures a regular flow of request processing and actions.
- **Status Monitoring and Logging:** Monitors the status of operations and logs them.

## Usage Scenarios
Repeat And Replace is ideal for use in the following scenarios:
- Repeated and regular request sending in penetration tests.
- Testing applications requiring complex session mechanisms.
- Extracting specific data from requests and responses for reuse.
- Applying automatic and continuous configuration changes.

---

# Installation

## Configuration
1. Download the `snakeyaml.jar` file. This library is required to convert YAML files into a format that the extension can understand.
   
2. Open Burp Suite and go to the "Extender" tab.

3. Find the "Options" sub-tab and add the path to the `snakeyaml.jar` file in the "Java Environment" section. This is necessary for the extension to process YAML files.

## Installing the Extension
1. Return to the "Extender" tab within Burp Suite.

2. Navigate to the "Extensions" sub-tab and click on the "Add" button.

3. In the dialog box that opens, select "Java" as the "Extension Type."

4. Click the "Select file..." button and choose the `.jar` extension file for the "Repeat And Replace" extension.

5. After selecting the extension, complete the installation by clicking the "Next" or "Finish" button.

Once the installation is complete, the Repeat And Replace extension will be active within Burp Suite and ready for use.

For more information on how to prepare the configuration file and how to use the extension, please refer to the extension documentation.

# Creating a Configuration File 

## Creating the Skeleton of the Configuration File
Start by establishing the general structure of the configuration file. This structure defines the basic sections of the file.

```yaml
name: application_name_config

matchers: []

from: []

repeat: []

replacer: []
```

### Defining the Matcher Section

The Matcher section contains conditions that specify when the extension should be triggered. In the Matcher structure, the innermost list (working with "AND" logic) requires all conditions within that group to be met simultaneously, while the outermost list (working with "OR" logic) represents an alternative group of conditions. 

Each "AND" group (inner lists starting with `-`) signifies that all conditions within that group must be met for the extension to trigger. If there are multiple "AND" groups within an outer list, the extension will trigger when any of these groups' conditions are met ("OR" logic).

```yaml
matchers:
  # This list works with "OR" logic - The extension triggers if any of the listed groups match.
  - # The following list works with "AND" logic - All conditions within this group must be met.
    - from: request_header
      contains:
        - 'POST /test5'
      regex: false
    - from: response_body
      contains:
        - 'Error'
  - # This is another "AND" group and is related to the previous group with "OR" logic.
    - from: request_body
      contains:
        - '"token": "'
    - from: response_header
      contains:
        - '403'
```

In the Matcher structure, each `contains` list is evaluated with "AND" logic, meaning data from a `from` source must contain all the specified values in the `contains` list. The outermost list indicates that these groups are alternatives, and the extension will trigger when any group matches.

The regex option can be optionally specified for each matching rule. If regular expressions are desired for a specific match, it can be indicated as `regex: true`, otherwise, you can omit this field or leave it as `regex: false`.

### Defining the Source Module
In the `from` section, specify which traffic from Burp Suite modules should be processed based on the conditions defined in the matcher section.

```yaml
from:
  - Repeater
  - Scanner
  - Proxy
  - Intruder
```

This section determines which Burp Suite modules the extension will monitor. Setting this section directly affects the scope and functionality of your extension.

### Repeating Requests
The `repeat` section defines how a request will be repeated. Requests can be copied using the "Repeat And Replace" feature in Burp Suite.

```yaml
repeat:
  - raw_request: |
      GET /test_endpoint HTTP/1.1
      Host: example.com
      # Other HTTP headers...
    service:
      protocol: http
      port: 80
      host: target.example.com
```

### Extracting and Using Values
The extraction operation is used to extract data from a specific response. This extracted data can be stored for later use in requests in the `replacer` section.

```yaml
extractor:
  - name: token_extractor
    from: response_body
    regex: '"token":\s*"(.+?)"'
```

### Replacing Values
In the `replacer` section, you specify the values to be used when constructing requests. These values can be information that was extracted and preserved with the extractor.

```yaml
replacer:
  - from: request_body
    replace_with: token_extractor
    regex: 'token_placeholder'
```

### Automatic Session Update

In addition to supporting multiple configurations, the extension makes automatic session management easier with the `continuousupdate` feature. This feature allows the extension to automatically obtain a new session token when a specific session expires and use this new token for all ongoing requests.

#### Continuous Update in Configuration

The setting `continuousupdate: true` indicates that the extension is operating in continuous update mode and is included in the general configuration settings. When this feature is enabled, the extension automatically triggers the `repeat` operations under certain conditions, fetching new session information and updating requests with this new information.

```yaml
continuousupdate: true

matchers:
  request:
    - - from: request_header
        contains:
          - "POST /test5"
          - "Host: localhost:5000"
          - "{\"token\":\""
  response:
    - - from: response_body
        contains:
         - "Session expired"
         - "Error"

replacers:
  - match: "SessionTokenPlaceholder"
    replace_with: "NEW_SESSION_TOKEN"
    scope: request_header

```

#### Automatic Update Flow

1. The extension checks the `matchers.request` conditions with each request.
2. If the conditions are met and a successful `matchers.response` result has been received before,

 the extension updates the current request with the new session value thanks to the `continuousupdate` feature.
3. If errors specified in `matchers.response` are detected, indicating that the session has expired, the extension typically triggers the `repeat` operations to obtain a new session.
4. After obtaining a new session, this value is used in the defined areas in the `replacers` section.
5. The process ensures that the session remains current without disrupting the user experience, and the extension automatically repeats this flow. This allows users to continue their work seamlessly even when the session expires.

### Loading and Using the Configuration File
After creating the configuration file, go to the extension's interface and click the "Add" button to select and open the file. After uploading the file, you will see the file name in the extension's interface. To activate the configuration, you need to press the "Reload" button.

### Supporting Multiple Configurations
The extension supports multiple configuration files, allowing you to maintain various configurations for different scenarios or tests and enable them as needed.

# Sample Scenarios and Configuration Files

Our extension comes with pre-prepared configuration files and application examples for various usage scenarios. These examples are designed to help you explore the power and flexibility of the extension and demonstrate how it can be applied to real-world scenarios.

#### Session Renewal Example

Situations that require a special configuration for session management can be handled using the `continuousupdate` feature. For example, if a session expires and needs to be renewed, the extension can perform this process automatically. You can find an example configuration file that includes this feature and demonstrates how to use it in the `examples/session-update` folder.

In this folder, you can find files that explain how tokens that need to be renewed automatically when the session expires are handled. The example scenario demonstrates how the extension detects that the session has expired using the response matcher and, thanks to the `continuousupdate` feature, continues the process by obtaining a new session token.

#### Standard Request Repeating Example

Examples for a standard scenario that allows a specific flow to be repeated every time a request is made are available in the `examples/standard-repeat` folder. These examples explain step by step how to use matcher and replacer configurations, how to modify a request, and how to repeat requests.

These examples cover scenarios such as automatically changing requests under certain conditions or adding specific headers. Users can customize these examples to suit their needs and use them to create their own flows.

#### Using the Examples

By examining the sample configuration files and usage scenarios for both scenarios, you can learn how to use the extension and apply it to your own situation. Exploring these examples will help you better understand the functionality of the extension and show you how to use the features that are most suitable for your needs.

Visit the [examples](examples/) folder to discover the versatility and user-friendliness of our extension and learn how to integrate it into your own usage scenarios.
