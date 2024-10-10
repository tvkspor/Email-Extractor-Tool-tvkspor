import email
import email.parser
import sys

def read_file(file_path):
    with open(file_path, 'rb') as file:
        content_file = file.read()
    parser = email.parser.BytesParser()
    msg = parser.parsebytes(content_file)
    return msg

def main(file_path):
    msg = read_file(file_path)

    print("From", msg['From'])
    print("To", msg['From'])
    print("Subject:", msg['Subject'])
    print("Date:", msg['Date'])
    if msg.is_multipart():
        for part in msg.iter_parts():
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition")

            if content_disposition is None:
                if content_type == "text/plain":
                    print("Body:", part.get_payload(decode=True).decode(part.get_content_charset()))
    else:
        print("Body:", msg.get_payload(decode=True).decode(msg.get_content_charset()))

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print (f"Usage: python {sys.argv[0]} <file_path>")
        sys.exit(1)
    file_path = sys.argv[1]
    main(file_path)