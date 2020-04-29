import requests
import os

SCOPE = "https://graph.microsoft.com/.default"
GRANT_TYPE = "client_credentials"
TOKEN_PAYLOAD = {"client_id": None,
                 "scope": SCOPE,
                 "client_secret": None,
                 "grant_type": GRANT_TYPE}

HEADERS = {"Content-Type": "application/json"}
UPDATE_ALERT_HEADER = {"Prefer": "return=representation"}

# urls
URL_AUTHORIZATION = "https://login.microsoftonline.com/{tenant}/adminconsent?client_id={client_id}&redirect_uri={redirect_uri}"
ACCESS_TOKEN_URL = 'https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token'

# if you want to use OS environment variables to store creds
CLIENT_ID = os.environ.get("CLIENT_ID")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET")
TENANT = os.environ.get("TENANT")
USER_NAME = os.environ.get("USER_NAME")

class O365GraphAPI(object):
    def __init__(self, client_id, client_secret, tenant, user_name, verify_ssl=False):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tenant = tenant
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.access_token = self.generate_token(self.client_id, self.client_secret,
                                                                         self.tenant)
        self.session.headers.update({"Authorization": "Bearer {0}".format(self.access_token)})
        self.user_id = self.user_id_by_name(user_name)

    def generate_token(self, client_id, client_secret, tenant):
        """
        Request access token (Valid for 60 min)
        :param client_id: {string} The Application ID that the registration portal
        :param client_secret: {string} The application secret that you created in the app registration portal for your app.
        :param tenant: {string} domain name from azure portal
        :return: {string} Access token. The app can use this token in calls to Microsoft Graph.
        """
        payload = TOKEN_PAYLOAD
        payload["client_id"] = client_id
        payload["client_secret"] = client_secret
        res = requests.post(ACCESS_TOKEN_URL.format(tenant=tenant), data=payload)
        self.validate_response(res)
        return res.json().get('access_token')

    def validate_response(self, response):
        try:
            response.raise_for_status()
        except requests.HTTPError as error:
            raise error

    def user_list(self):
        url = 'https://graph.microsoft.com/v1.0/users/'
        res = requests.get(url, headers=self.session.headers)
        return res.json()

    def user_id_by_name(self, name):
        ul = self.user_list()
        for entry in ul['value']:
            if entry['userPrincipalName'].lower() == name.lower():
                return entry['id']
        return False

    def get_messages(self):
        url = f'https://graph.microsoft.com/v1.0/users/{self.user_id}/messages'
        res = requests.get(url, headers=self.session.headers)
        return res.json()['value']

    def get_messages_by_time(self, start_time):
        end_time = datetime.now().strftime("%Y:%m:%dT%H:%M:%SZ")
        url = f'https://graph.microsoft.com/v1.0/users/{self.user_id}/messages?$filter=(receivedDateTime ge {start_time}) and (receivedDateTime le {end_time})'  # YYYY-MM-DDThh:mm:ss.sssZ
        res = requests.get(url, headers=self.session.headers)
        return res.json()['value']

    def get_attachments(self, message_id):
        url = f'https://graph.microsoft.com/v1.0/users/{self.user_id}/messages/{message_id}/attachments'
        res = requests.get(url, headers=self.session.headers)
        return res.json()['value']
