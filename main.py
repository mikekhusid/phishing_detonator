from base64 import b64decode, b64encode
from email import message_from_string
from hashlib import sha256
import re
import os
import logging
from logging.handlers import RotatingFileHandler
from O365GraphAPI import O365GraphAPI
from VTLogic import VTAPI

OUTPUT_PATH = "/home/phishhunter/phish_script/{}"
LOGGING_PATH = "/home/phishhunter/logs/phish.log"
TIMESTAMP_FILE = "/home/phishhunter/phish_script/timestamp.txt"

# if you want to use OS environment variables to store creds
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
TENANT = os.environ.get("TENANT")
USER_NAME = os.environ.get("USER_NAME")

logger = logging.getLogger()
handler = RotatingFileHandler(LOGGING_PATH, maxBytes=2000, backupCount=10)
logger.addHandler(handler)

URLS_REGEX = r"(?i)(?:(?:(?:http|https)(?:://))|www(?!://))(?:[ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\-\._~:/\?#\[\]@!\$&'\(\)\*\+,=])+"


def flatten_save_payload(msg):
    '''Flattens payload and returns list of tuples.  Tuple consists of 3 elements:
    filename, filehash, b64 encoded file contents'''
    attachment_info = []
    for payload in msg.get_payload():
        x = payload.get_payload()
        if isinstance(x, list):
            flatten_save_payload(payload)
        else:
            filename = payload.get_filename()
            if filename:
                file_contents = payload.get_payload(decode=True)
                filehash = sha256(file_contents).hexdigest()
                attachment_info.append((filename, filehash, b64encode(file_contents)))
    return attachment_info


def get_body(msg):
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdispo = str(part.get('Content-Disposition'))
            # skip any text/plain (txt) attachments
            if ctype == 'text/plain' and 'attachment' not in cdispo:
                body = part.get_payload(decode=True)
                return body  # decode
    # not multipart - i.e. plain text, no attachments
    else:
        body = msg.get_payload(decode=True)
        return body


def check_if_eml(all_attachments):
    for attachment in all_attachments:
        if attachment['name'].endswith('.eml'):
            try:
                content = attachment['contentBytes']
                if content:
                    attached_email = b64decode(content).decode('utf8')
                    return attached_email
            except:
                raise


def build_iocs(attached_email):
    msg = message_from_string(attached_email)
    headers = dict(msg._headers)
    message_id_header = headers['Message-ID'].strip(r"<>$@!\/")
    attachment_info = flatten_save_payload(msg)
    if attachment_info:
        # make a file to save the attachments to so we can submit filepaths to VT, etc. later on
        os.mkdir(OUTPUT_PATH.format(message_id_header))
        for attachment in attachment_info:
            # filename going to be element 1 of the attachment tuple.  hash is 2.  b64 contents is 3.
            with open(os.path.join(OUTPUT_PATH.format(message_id_header), attachment[0]), 'wb') as f:
                f.write(b64decode(attachment[2]))
    body = get_body(msg)
    urls = re.findall(URLS_REGEX, str(body), re.DOTALL)
    iocs = dict({'headers': headers, 'attachment_info': attachment_info, 'body': body, 'urls': urls})
    return iocs


def analyze_iocs_with_vt(iocs):
    vt = VTAPI()
    for attachment in iocs['attachment_info']:
        res = vt.hash_scan(attachment[1])
        res.raise_for_status()


def get_timestamp():
    with open(TIMESTAMP_FILE, 'r') as f:
        f.read(timestamp)


def save_timestamp(timestamp):
    with open(TIMESTAMP_FILE, 'w') as f:
        f.write(timestamp)


def main():
    last_timestamp = ''
    ms = O365GraphAPI(CLIENT_ID, CLIENT_SECRET, TENANT, USER_NAME, verify_ssl=True)
    all_messages_retrieved = ms.get_messages()  # TODO by time
    for message in all_messages_retrieved:
        msg_id = message['id']
        all_attachments = ms.get_attachments(msg_id)
        # check_if_eml assumes only one EML attached to the forwarded message
        attached_email = check_if_eml(all_attachments)
        if attached_email:
            iocs = build_iocs(attached_email)
        if message['createdDateTime'] > last_timestamp:
            last_timestamp = message['createdDateTime']
    if last_timestamp != '':
        save_timestamp(last_timestamp)
