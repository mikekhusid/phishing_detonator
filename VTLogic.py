import requests
import os
from urllib.parse import urljoin
import json
import time

API_ROOT = 'https://www.virustotal.com/vtapi/v2/'
VT_KEY = os.environ.get("VT_KEY")
PARAMS = {'apikey': VT_KEY}


class VTAPI(object):

    def hash_scan(self, hash):
        url = urljoin(API_ROOT, 'file/report')
        PARAMS['resource'] = hash
        response = requests.get(url, params=PARAMS)
        if self.translate_response(response.json()) == True:
            return response.json()
        else:
            hash_scan(self, hash)

    def file_scan(self, filename, filepath):
        url = urljoin(API_ROOT, 'file/scan')
        files = {'file': (filename, open(filepath, 'rb'))}
        response = requests.post(url, files=files, params=PARAMS)
        return response.json()

    def translate_response(self, response):
        '''
        from VT: response_code: if the item you searched for was not present in VirusTotal's dataset this result will be 0. If the requested item is still queued for analysis it will be -2. If the item was indeed present and it could be retrieved it will be 1. Any other case is detailed in the full reference.
        '''
        response = json.loads(response)
        code = response['response_code']
        if code == 1:
            return True
        if code == -2:
            time.sleep(60)
            translate_response(json.dumps(response))
        if code == 0:
            return False
