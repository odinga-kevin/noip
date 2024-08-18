import requests
import sys
import re
import ipaddress
import os
import pickle
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import base64
import datetime
import time
from slugify import slugify

class noIP:
    '''
        Required positional arguments:
            email: your no-ip login email
            password: your no-ip password
        Usage example: noip = noIP(your-no-ip-email, your-password)
    '''
    def __init__(self, email, password):
        self.cookie_file = 'no_ip_cookie.pkl'
        self.session = requests.Session()
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
        self.session.headers.update(headers)

        if os.path.exists(self.cookie_file):
            self.cookies = self.load_cookies()
            self.session.cookies.update(self.cookies)
        
        response = self.session.get('https://my.noip.com/')
        
        if 'login' in response.url:
            print('Session expired, signing in...')
            csrfToken = re.search(r'"csrf-token" content="(.*?)"', response.text).group(1)
            self.token = self.login(email, password, csrfToken)
            self.save_cookies()
        else:
            self.token = re.search(r'name="token" content="(.*?)"', response.text).group(1)
            self.save_cookies()

    def save_cookies(self):
        with open(self.cookie_file, 'wb') as f:
            pickle.dump(self.session.cookies, f)
            
    def load_cookies(self):
        with open(self.cookie_file, 'rb') as f:
            return pickle.load(f)
    
    def getLoginToken(self):
        '''
            Returns a csrf token used to log in
        '''
        url = "https://www.noip.com/login"
        html = self.session.get(url).text

        csrfToken = re.search(r'"csrf-token" content="(.*?)"', html).group(1)
        return csrfToken

    def login(self, email, password):
        '''
            Logs in and returns 'X-CSRF-TOKEN' for subsequent requests
        '''
        data = {
            '_token': self.getLoginToken(),
            'username': email,
            'password': password,
            'submit_login_page': '1',
            'intended_hash': '',
            'g-recaptcha-response': '',
        }
        
        headers = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
        
        html = self.session.post('https://www.noip.com/login', headers=headers, data=data)
        
        if 'verify' in html.url:
            print('Verification required...')
            print('Waiting for verification code...')
            csrfToken = re.search(r'"csrf-token" content="(.*?)"', html.text).group(1)
            def extract_integers_from_string(s):
                result = []
                temp = ''
                for char in s:
                    if char.isdigit():
                        temp += char
                    elif temp:
                        result.append(int(temp))
                        temp = ''
                if temp:
                    result.append(int(temp))
                return result
            
            time.sleep(20)
            
            date_5_days_ago = (datetime.datetime.utcnow() - datetime.timedelta(days=5)).date()
            query = f'after:{date_5_days_ago} No-IP'
            
            gmail = gMail()
            
            codeReceived = False
            challenge_code = None
            trial_limit = 10
            trials = 0
            
            while not codeReceived and trials < trial_limit:
                emails = gmail.get_emails(query)
                if emails:
                    for email in emails:
                        try:
                            if time.time() - email['date'] < 90 and slugify('Verification Code') in slugify(email['subject']):
                                challenge_code = extract_integers_from_string(email['subject'])[0]
                                codeReceived = True
                                break
                        except:
                            continue
                
                trials += 1
                if not codeReceived:
                    time.sleep(10)
                
            
            if not challenge_code:
                raise Exception('Error getting verification code')
            
            
            data = {
                'type': 'email_pin',
                'challenge_code': int(challenge_code),
                'trust_device': 1,
                'submit': 'Verify',
                '_token': csrfToken,
            }
            
            headers = {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36'}
            
            html = self.session.post('https://www.noip.com/2fa/verify', headers=headers, data=data)
            
        if 'login' not in html.url:
            print("Login successful...")
            token = re.search(r'name="token" content="(.*?)"', html.text).group(1)
            return token
        else:
            raise Exception("Log in failed...")
        
    def checkMyHostnames(self):
        '''
            Retrieves all no-ip domains and updates those expiring in 7 days
        '''
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36', 'X-CSRF-TOKEN': self.token, 'X-Requested-With': 'XMLHttpRequest'}
        names = self.session.get('https://my.noip.com/dns/names', headers=headers).json()['data']
        for name in names:
            daysRemaining = name['days_remaining']
            hostName = name['hostname']
            hostID = name['id']
            if daysRemaining <= 7:
                print(f"Confirming '{hostName}', {daysRemaining} days remaining...")
                res = self.session.get(f'https://my.noip.com/api/host/{hostID}/touch', headers=headers).json()
                if not res['success']:
                    raise Exception(f"{hostName} Confirmation failed...\n {res}")
                else:
                    print(f"{hostName} Confirmed succesfully... {res['host']['days_remaining']} days remaining...")
            else:
                print(f"'{hostName}' not due for confirmation, {daysRemaining} days remaining...")
        
    def addNewHostname(self, hostname, _domain=None, record_type=None, ipv4=None, ipv6=None, cname=None, web_redirect_url=None):
        '''
            Creates the given hostname in the given domain using one of the 4 record types: ipv4 (A), ipv6 (AAA), cname, and web redirect. The default domain and record type are 'ddns.net' and 'ipv4', respectively.
            
            Takes the following arguments:
            hostname: A prefix of a domain name e.g. 'api' without 'ddns.net'.
            
            domain: The host to attach the new hostname to e.g. 'ddns.net'. The default domain is 'ddns.net' Check the noip website for available free hosts.
            
            record_type: The record type to use when creating a new hostname.
                        Valid options are: 'ipv4', 'ipv6', 'cname', and 'web-redirect'. 'ipv4' is used as the default if none is specified. Record type is also infered from 'ipv4', 'ipv6', 'cname', and 'web-redirect-url' options. E.g., if 'ipv6' is provided, the 'ipv6' record_type is automatically used.
                        
                        {ipv4}: 'ipv4' address required if this record type is selected, current ip is used as the default.
                        {ipv6}: both 'ipv4' and 'ipv6' addresses are required when this record type is selected, current ip is used as the default.
                        {cname}: requires the 'cname' e.g. 'example.domain.com'.
                        {web-redirect}: requires the url or ipv4 address where the url will redirect.
            
            ipv4: The ipv4 adddress. Current address is used when not provided. Required for both 'ipv4'(A) and 'ipv6'(AAAA) record types.
            ipv6: The ipv6 address. Required for the 'ipv6'(AAAA) record type.
            cname: The cname e.g. 'example.domain.com'. Required for the 'cname' record type
            web_redirect_url: The full web_redirect_url with protocol e.g. 'https://example.com' or 'http://10.67.1.1:8080/web'. Required for 'web-redirect' record type.
            
            Usage examples:
            noip = noip(email, pass)
            noip.addNewHostname('home-camera') #creates home-camera.ddns.net using current ipv4 address.
            noip.addNewHostname('home-camera', record-type='ipv6', ipv6='2001:0db8:85a3:0000:0000:8a2e:0370:7334' ipv4='30.5.7.8') #creates ipv6 record type
            noip.addNewHostname('home-camera', ipv6='2001:0db8:85a3:0000:0000:8a2e:0370:7334') #creates ipv6 record type. The current ipv4 address is used.
            noip.addNewHostname('home-camera', ipv4='30.5.7.8') #creates home-camera.ddns.net using the provided ipv4 address, useful for remote servers.
            noip.addNewHostname('home-camera', record-type=cname cname="example.com")
            noip.addNewHostname('home-camera', record-type=web-redirect web_redirect_url="https://example.com") #the web redirect record is created with the mask URL option unchecked.
            
            Server response is printed if hostname creation fails e.g. when the provided hostname already exists.
        '''
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36', 'X-CSRF-TOKEN': self.token, 'X-Requested-With': 'XMLHttpRequest'}
        hosts = self.session.get('https://my.noip.com/dns/names', headers=headers).json()
        
        host_count = hosts['host_count']
        host_limit = hosts['host_limit']
        
        if host_count == host_limit:
            raise Exception("Maximum number of hostnames allowed for your account already created...")
        
        def create_ipv4(name, domain, ipv4_address):
            post_data = {
                'id': 0,
                'target': ipv4_address,
                'name': name,
                'domain': domain,
                'wildcard': False,
                'type': 'A',
                'ipv6': '',
                'url': {
                    'scheme': 'http',
                    'is_masq': False,
                    'masq_title': '',
                    'meta_desc': '',
                    'meta_keywords': '',
                },
                'is_offline': False,
                'offline_settings': {
                    'action': 'noop',
                    'ip': '',
                    'url': '',
                    'protocol': 'http',
                    'page': {
                        'title': '',
                        'image_url': '',
                        'text': '',
                        'email': '',
                    },
                },
                'mx_records': [],
            }
            return post_data
        
        def create_ipv6(name, domain, ipv4_address, ipv6_address):
            post_data = {
                'id': 0,
                'target': ipv4_address,
                'name': name,
                'domain': domain,
                'wildcard': False,
                'type': 'AAAA',
                'ipv6': ipv6_address,
                'url': {
                    'scheme': 'http',
                    'is_masq': False,
                    'masq_title': '',
                    'meta_desc': '',
                    'meta_keywords': '',
                },
                'is_offline': False,
                'offline_settings': {
                    'action': 'noop',
                    'ip': '',
                    'url': '',
                    'protocol': 'http',
                    'page': {
                        'title': '',
                        'image_url': '',
                        'text': '',
                        'email': '',
                    },
                },
                'mx_records': [],
            }
            return post_data
        
        def create_cname(name, domain, cname):
            post_data = {
                'id': 0,
                'target': cname,
                'name': name,
                'domain': domain,
                'wildcard': False,
                'type': 'CNAME',
                'ipv6': '',
                'url': {
                    'scheme': 'http',
                    'is_masq': False,
                    'masq_title': '',
                    'meta_desc': '',
                    'meta_keywords': '',
                },
                'is_offline': False,
                'offline_settings': {
                    'action': 'noop',
                    'ip': '',
                    'url': '',
                    'protocol': 'http',
                    'page': {
                        'title': '',
                        'image_url': '',
                        'text': '',
                        'email': '',
                    },
                },
                'mx_records': [],
            }
            return post_data
        def create_web_redirect(name, domain, protocol, url):
            post_data = {
                'id': 0,
                'target': url,
                'name': name,
                'domain': domain,
                'wildcard': False,
                'type': 'URL',
                'ipv6': '',
                'url': {
                    'scheme': protocol,
                    'is_masq': False,
                    'masq_title': '',
                    'meta_desc': '',
                    'meta_keywords': '',
                },
                'is_offline': False,
                'offline_settings': {
                    'action': 'noop',
                    'ip': '',
                    'url': '',
                    'protocol': 'http',
                    'page': {
                        'title': '',
                        'image_url': '',
                        'text': '',
                        'email': '',
                    },
                },
                'mx_records': [],
            }
            return post_data
                        
        domain = _domain if _domain is not None else 'ddns.net'
        if (record_type is None and ipv6 is None and cname is None and web_redirect_url is None) or (record_type == 'ipv4'):
            print(f"Creating '{hostname}.{domain}' with record type 'ipv4 (A)'")
            ipv4_a = ipv4 if ipv4 is not None else requests.get('https://api.ipify.org').text
                
            if ipaddress.ip_address(ipv4_a).version != 4:
                raise Exception('Provide a valid ipv4 address...')
            
            post_data = create_ipv4(hostname, domain, ipv4_a)
        elif (record_type is None and ipv6 is not None) or (record_type == 'ipv6'):
            print(f"Creating '{hostname}.{domain}' with record type 'ipv6 (AAAA)'")
            try:
                ipv6_a = ipv6 if ipv6 is not None else requests.get('https://api6.ipify.org').text
            except Exception:
                sys.exit('Provide a valid ipv6 address...')
            
            if ipaddress.ip_address(ipv6_a).version != 6:
                raise Exception('Provide a valid ipv6 address...')
            
            ipv4_a = ipv4 if ipv4 is not None else requests.get('https://api.ipify.org').text
            
            if ipaddress.ip_address(ipv4_a).version != 4:
                raise Exception('Provide a valid ipv4 address...')
            
            post_data = create_ipv6(hostname, domain, ipv4_a, ipv6_a)
        elif (record_type is None and cname is not None) or (record_type == 'cname'):
            print(f"Creating '{hostname}.{domain}' with record type 'cname' (DNS Alias)")
            if record_type == 'cname' and cname is None:
                raise Exception("A valid cname is required for record type 'cname'")
            
            post_data = create_cname(hostname, domain, cname)
        elif (record_type is None and web_redirect_url is not None) or (record_type == 'web-redirect'):
            print(f"Creating '{hostname}.{domain}' with record type 'web-redirect'")
            if record_type == 'web-redirect' and web_redirect_url is None:
                raise Exception("Full redirect url with protocol e.g. 'https://example.com/path' is required for the record type 'web-redirect'")
            protocol = web_redirect_url.split('://')[0]
            url = web_redirect_url.split('://')[-1]
            
            post_data = create_web_redirect(hostname, domain, protocol, url)
            
        try:
            res = self.session.post('https://my.noip.com/dns/names', headers=headers, json=post_data)
            j_res = res.json()
            if 'hostname' in j_res:
                print(f"Created '{j_res['hostname']}', hostID = {j_res['id']}, Target = {j_res['target']}")
            else:
                raise Exception(f"Adding '{hostname}.{domain}' failed...\n {res.text}")
        except Exception as e:
            print(f"Error: {e}")
    
    def deleteHostname(self, hostname):
        '''
            Deletes the given hostname
        '''
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36', 'X-CSRF-TOKEN': self.token, 'X-Requested-With': 'XMLHttpRequest'}
        res = self.session.delete(f'https://my.noip.com/dns/names/{hostname}', headers=headers)
        j_res = res.json()
        currentNames = []
        for name in j_res['data']:
            hostName = name['hostname']
            currentNames.append(hostName)
        
        if hostname not in currentNames:
            print(f"'{hostname}' deleted succesfully...")
        else:
            raise Exception(f"Deleting '{hostname}' failed...\n {res.text}")
    
    def updateHostname(self, hostname, ipv4_address=None, ipv6_address=None):
        '''
            Updates the given hostname with the give ip addresses. If no ip address is given, the current ip will be used.
            Currently supports hostnames with record types 'ipv4(A) and 'ipv6'(AAAA)
        '''
        headers = {'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36', 'X-CSRF-TOKEN': self.token, 'X-Requested-With': 'XMLHttpRequest'}
        HostData = self.session.get(f"https://my.noip.com/dns/names/{hostname}", headers=headers).json()
        # Cannot update name
        HostData.pop('name')
        
        or_target = HostData['target']
        
        supported_types = ['A', 'AAAA']
        record_type = HostData['type']
        
        if record_type not in supported_types:
            raise Exception(f"Support for {record_type} update not implemented")
        
        if record_type == 'A':
            _ip_address = ipv4_address if ipv4_address is not None else requests.get('https://api.ipify.org').text
            
            if ipaddress.ip_address(_ip_address).version != 4:
                raise Exception('Provide a valid ipv4 address...')
        elif record_type == 'AAAA':
            try:
                _ip_address = ipv6_address if ipv6_address is not None else requests.get('https://api6.ipify.org').text
            except Exception:
                sys.exit('Provide a valid ipv6 address...')
                
            if ipaddress.ip_address(_ip_address).version != 6:
                raise Exception('Provide a valid ipv6 address...')
        
        HostData['target'] = _ip_address
        
        try:
            res = self.session.patch(f"https://my.noip.com/dns/names/{hostname}", headers=headers, json=HostData)
            j_res = res.json()
            if j_res['target'] == _ip_address:
                print(f"Target for '{hostname}' updated from {or_target} to {j_res['target']}...")
            else:
                raise Exception(f"Updating '{hostname}' failed...\n {res.text}")
        except Exception as e:
            print(f"Error: {e}")
        
class gMail:
    def __init__(self):
        self.token_cache_path = 'gmail_token.pickle'
        self.credentials_json_path = 'gmail_credentials.json'
    
    def get_service(self):
        creds = None
        # The file self.token_cache_path stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if os.path.exists(self.token_cache_path):
            with open(self.token_cache_path, 'rb') as token:
                creds = pickle.load(token)
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    self.credentials_json_path, SCOPES)
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open(self.token_cache_path, 'wb') as token:
                pickle.dump(creds, token)

        service = build('gmail', 'v1', credentials=creds)
        return service

    def get_emails(self, query):
        service = self.get_service()
        results = service.users().messages().list(userId='me', q=query).execute()
        messages = results.get('messages', [])
        emails = []

        if not messages:
            print('No messages found.')
        else:
            for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                payload = msg['payload']
                headers = payload.get('headers', [])
                
                # Find the sender's email address
                sender = None
                subject = None
                received_date = None
                for header in headers:
                    if header['name'] == 'From':
                        sender = header['value']
                    if header['name'] == 'Subject':
                        subject = header['value']
                    if header['name'] == 'Date':
                        date_format = '%a, %d %b %Y %H:%M:%S %z (%Z)'
                        date_object = datetime.datetime.strptime(header['value'], date_format)
                        received_date = date_object.timestamp()

                # Extract the message body
                body = ""
                if 'data' in payload['body']:
                    body = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8')
                else:
                    parts = payload.get('parts', [])
                    for part in parts:
                        if 'data' in part['body']:
                            body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                            break

                emails.append({'sender': sender, 'subject': subject, 'date': received_date, 'body': body})
        return emails
