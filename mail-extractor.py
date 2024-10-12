import email
import email.parser
import sys
import re
import ipaddress
from email.header import decode_header 
import hashlib
import ipinfo
import requests

def read_file(file_path):
    with open(file_path, 'rb') as file:
        content_file = file.read()
    parser = email.parser.BytesParser()
    msg = parser.parsebytes(content_file)
    return msg

def get_ip(email_message):
    ip_set = set()   
    
    # Extract IP addresses from headers 
    for header_name, header_value in email_message.items():
        if isinstance(header_value, (str, bytes)):
            # If string or bytes find IP
            ip_set.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', header_value))
        else:
            # If not print err
            print(f"Error: header_value for '{header_name}' is not a string or bytes, got: {type(header_value)}")

    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain' or content_type == 'text/html':
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            ip_set.update(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', payload))
    
    valid_ip_set = []

    for ip in ip_set:
        try: 
            ip_lookup(ip)
            ipaddress.ip_address(ip)
            valid_ip_set.append(ip)
        except ValueError:
            pass
    return list(set(valid_ip_set))

def get_url(email_message):
    url_set = set()
    for part in email_message.walk():
        content_type = part.get_content_type()
        if content_type == 'text/plain' or content_type == 'text/html':
            payload = part.get_payload(decode=True)
            if isinstance(payload, bytes):
                payload = payload.decode('utf-8', errors='ignore')
            url_set.update(re.findall(r'https?:\/\/(?:[\w\-]+\.)+[a-z]{2,}(?:\/[\w\-\.\/?%&=]*)?', payload))
    return list(url_set)

def get_header(email_message):
    headers_need=[
        "Date",
        "Subject",
        "To",
        "From",
        "Reply-To",
        "Return-Path",
        "Message-ID",
        "X-Originating-IP",
        "X-Sender-IP",
        "Authentication-Results"
    ]
    headers={}
    for key in email_message.keys():
        if key in headers_need:
            headers[key]= email_message[key]
    return headers

def get_attachment(email_message):
    attachments =[]
    for part in email_message.walk():
        if part.get_content_maintype() == 'multipart':
            continue   
        if part.get('Content-Disposition') is None:
            continue
        file_name = part.get_filename()
        if file_name:
            attachments.append({
                'filename': file_name,
                'md5': hashlib.md5(part.get_payload(decode=True)).hexdigest(),
                'sha1': hashlib.sha1(part.get_payload(decode=True)).hexdigest(),
                'sha256': hashlib.sha256(part.get_payload(decode=True)).hexdigest()
            })

    return attachments

def check_reversed_ip(ip):
    private_ranges = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
    ]
    reserved_ranges = [
        '0.0.0.0/8',
        '100.64.0.0/10',
        '169.254.0.0/16',
        '192.0.0.0/24',
        '192.0.2.0/24',
        '198.51.100.0/24',
        '203.0.113.0/24',
        '224.0.0.0/4',
        '240.0.0.0/4',
    ]
    for r in private_ranges + reserved_ranges:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(r):
            return True
    return False

def ipinfo(ip):
    response = requests.get(f"https://ipinfo.io/{ip}/json")
    if response.status_code != 200:
        raise Exception(f"Failed to get IP info for {ip}")
    return response.json()

def ip_lookup(ip):
    if check_reversed_ip(ip):
        return None
    
    ip_info = ipinfo(ip)
    print(f"City: {ip_info.get('city', 'N/A')}")
    print(f"Location: {ip_info.get('loc', 'N/A')}")
    print(f"Region: {ip_info.get('region', 'N/A')}")
    print(f"Country: {ip_info.get('country', 'N/A')}")
    print(f"Organization: {ip_info.get('org', 'N/A')}")
    ip_fang = defangip(ip_info.get('ip', 'N/A'))
    print(f"IP: {ip_fang}")
    return ip_info

# Defang data for safer use
def defangip(ip):
    return ip.replace('.','[.]')
def defangurl(url):
    url.replace('.','[.]')
    url.replace('https://','hxxps[://]')

def main(file_path):
    email_message = read_file(file_path)
    ips = get_ip(email_message)
    urls = get_url(email_message)
    attachments = get_attachment(email_message)
    headers = get_header(email_message)

    print("Get ips from email_message") 
    print("#############")

    for ip in ips:
        ipinfo(ips)
        
    print("\nGet urls from email_message") 
    print("#############")

    for url in urls:
        print(defangurl(url))
    
    print("\nGet headers from email_message") 
    print("#############")

    for key, value in headers.items():
        print(f"{key}: {value}")

    print("\nGet attachments from email_message") 
    print("#############")

    for attachment in attachments:
        print(f"Filename: {attachment['filename']}")
        print(f"md5_hash: {attachment['md5']}")
        print(f"sha1_hash: {attachment['sha1']}")
        print(f"sha256_hash: {attachment['sha256']}")
        


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print (f"Usage: python {sys.argv[0]} <file_path>")
        sys.exit(1)
    file_path = sys.argv[1]
    main(file_path)