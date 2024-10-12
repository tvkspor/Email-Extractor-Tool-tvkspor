
# EMAIL EXTRACTOR TOOL 
Use for studying purpose only

# Overview

The Email Extractor Tool is a Python script designed to parse email files, extract various components such as IP addresses, URLs, headers, and attachments, and display detailed information about these components. This tool can be particularly useful for security analysts and investigators who need to analyze email contents for forensic purposes.

# Features
1. **Read Email File**: Reads an email file in `.eml` format.
2. **Extract IP Addresses**: Extracts IP addresses from email headers and body.
3. **Extract URLs**: Extracts URLs from the email body.
4. **Extract Headers**: Extracts specific headers such as "Date", "Subject", "To", "From", and others.
5. **Extract Attachments**: Extracts attachment filenames and their hash values (MD5, SHA1, SHA256).
6. **IP Information Lookup**: Looks up geolocation and other details for extracted IP addresses using the ipinfo.io service.
7. **Defang URLs and IPs**: Defangs URLs and IPs for safer handling.

# Installation

## Prerequisites
 - Python 3.x

The following Python libraries:

- `requests`
- `email`
- `ipaddress`
- `re`
- `hashlib`

## Install Required Libraries

```bash
pip install requests
```
# Usage
To use the tool, run the script with the path to the email file as an argument:

```bash 
python mail-extractor.py <file_path>
```


# Example Output
```bash
Get ips from email_message
#############
City: Mountain View
Location: 37.3860,-122.0840
Region: California
Country: US
Organization: AS15169 Google LLC
IP: 8[.]8[.]8[.]8

Get urls from email_message
#############
hxxps://example[.]com

Get headers from email_message
#############
Date: Thu, 21 Dec 2023 16:01:07 +0000
Subject: Test Email
To: recipient@example.com
From: sender@example.com
Reply-To: sender@example.com
Return-Path: <sender@example.com>
Message-ID: <1234567890@example.com>
X-Originating-IP: 192.0.2.1
X-Sender-IP: 198.51.100.1
Authentication-Results: example.com; spf=pass (sender IP is 192.0.2.1) smtp.mailfrom=sender@example.com

Get attachments from email_message
#############
Filename: attachment.txt
md5_hash: 098f6bcd4621d373cade4e832627b4f6
sha1_hash: a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
sha256_hash: 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

# Contrubutions

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.
