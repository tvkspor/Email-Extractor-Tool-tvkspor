import email
import email.parser
import sys
import re
import ipaddress
from email.header import decode_header 

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

# Defang data for safer use
def defangip(ip):
    return ip.replace('.','[.]')
def defangip(url):
    url.replace('.','[.]')
    url.replace('https://','hxxps[://]')

def main(file_path):
    email_message = read_file(file_path)
    ips = get_ip(email_message)
    print(ips)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print (f"Usage: python {sys.argv[0]} <file_path>")
        sys.exit(1)
    file_path = sys.argv[1]
    main(file_path)