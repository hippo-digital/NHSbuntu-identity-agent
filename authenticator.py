import base64
import requests
import re
from jinja2 import Template
import random
import string
import platform
import json

import cms
import card

import logging

class authenticator:
    def __init__(self):
        self.gac_version = 'GACv10. 0. 0. 1'
        self.pkcs11lib = '/usr/lib/ClassicClient/libgclib.so'
        self.auth_uri = 'http://10.211.55.3:5000'
        self.auth_uri = 'https://gas.nis1.national.ncrs.nhs.uk'
        self.ip_address = '127.0.0.1'
        self.device_id = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(8))

        self.auth_session = {}
        self.user_agent = 'Mozilla/4.0(compatible;IE;%s)' % self.gac_version

        self.smime_header = """MIME-Version: 1.0
        Content-Disposition: attachment; filename="smime.p7m"
        Content-Type: application/x-pkcs7-mime; name="smime.p7m"
        Content-Transfer-Encoding: base64
        
        """

        self.auth_activate_template = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE USER SYSTEM "gpOBJECT.DTD">
        <gpOBJECT>
        <gpPARAM name="auth_method">3</gpPARAM>
        <gpPARAM name="app_url">NHST</gpPARAM>
        <gpPARAM name="log_session_id">{{ session_id }}</gpPARAM>
        <gpPARAM name="device_id">{{ device_id }},ClientIP={{ ip }}</gpPARAM>
        <gpPARAM name="service">ACTIVATION</gpPARAM>
        </gpOBJECT>"""

        self.auth_validate_template = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE USER SYSTEM "gpOBJECT.DTD">
        <gpOBJECT>
        <gpPARAM name="auth_method">3</gpPARAM>
        <gpPARAM name="app_url">NHST</gpPARAM>
        <gpPARAM name="log_session_id">{{ session_id }}</gpPARAM>
        <gpPARAM name="device_id">{{ device_id }},ClientIP={{ ip }}</gpPARAM>
        <gpPARAM name="service">AUTHENTICATION</gpPARAM>
        <gpPARAM name="challenge">{{ challenge }}</gpPARAM>
        <gpPARAM name="signature">{{ signature }}</gpPARAM>
        <gpPARAM name="uid">{{ uid }}</gpPARAM>
        <gpPARAM name="card_type">p11</gpPARAM>
        <gpPARAM name="response" encoding="base64">{{ response }}</gpPARAM>
        <gpPARAM name="mobility">0</gpPARAM>
        </gpOBJECT>"""

        self.auth_logout_template = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE USER SYSTEM "gpOBJECT.DTD">
        <gpOBJECT>
        <gpPARAM name="service">LOGOUT</gpPARAM>
        <gpPARAM name="sso_ticket">{{ ticket }}</gpPARAM>
        <gpPARAM name="log_session_id">{{ session_id }}</gpPARAM>
        <gpPARAM name="device_id">{{ device_id }},ClientIP={{ ip }}</gpPARAM>
        <gpPARAM name="uid">{{ uid }}</gpPARAM>
        </gpOBJECT>"""

        self.analytics = {
            'OSVersion': platform.platform(),
            'Mode': 'Normal',
            'TrainingMode': 'False',
            'WinTabModeEnabled': 'False',
            'RemoteSession': 'False',
            'CardReaders': [],
            'ATR': None,
            'SessionId': None
        }

        self.role_select_uri = '%s/saml/RoleSelectionGP.jsp' % self.auth_uri

        self.log = logging.getLogger('authenticator')
        self.log.setLevel(logging.DEBUG)
        fh = logging.FileHandler('authenticator.log')
        fh.setLevel(logging.DEBUG)
        self.log.addHandler(fh)
        formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
        fh.setFormatter(formatter)
        self.log.info("Authenticator started")

    def authenticate(self, passcode, atr=None):
        session = {'id': ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10)),
                   'analytics': self.analytics.copy(),}

        session['analytics']['SessionId'] = session['id']
        session['analytics']['ATR'] = atr

        self._auth_activate(session)
        self.log.info('Method=authenticate, Message=Activate Received, Session=%s' % session)

        card.sign(self.pkcs11lib, passcode, session)
        self.log.info('Method=authenticate, Message=Challenge Signed, Session=%s' % session)

        self._auth_validate(session)
        self.log.info('Method=authenticate, Message=Validate Received, Session=%s' % session)

        self._role_select(session)
        self.log.info('Method=authenticate, Message=RoleSelect Received, Session=%s' % session)

        return session

    def logout(self):
        logout_body_template = Template(self.auth_logout_template)
        logout_body = logout_body_template.render(ticket = self.auth_params['sso_ticket'],
                                                  uid = self.auth_params['uid'],
                                                  device_id = self.device_id,
                                                  ip = self.ip_address,
                                                  session_id = self.session_id)

        requests.get(self.auth_params['sso_logout_url'],
                              verify=False,
                              headers={'User-Agent': self.user_agent},
                              data=logout_body)

    def _auth_activate(self, session):
        auth_activate_template = Template(self.auth_activate_template)
        auth_activate_body = auth_activate_template.render(device_id = self.device_id,
                                                  ip = self.ip_address,
                                                  session_id = session['id'])

        self.log.info('Method=_auth_activate, Message=Calling Activate, Body=%s' % auth_activate_body)

        auth_activate = requests.post('%s/login/authactivate' % self.auth_uri,
                                      verify=False,
                                      data=auth_activate_body,
                                      headers={'User-Agent': self.user_agent,
                                               'Analytics': json.dumps(session['analytics'])})

        body = auth_activate.content.decode('utf-8')

        self.log.info('Method=_auth_activate, Message=Activate Response Recevied, Status=%s, Body=%s' % (auth_activate.status_code, body))

        session['challenge'] = self._extract_parameter(body, 'challenge')
        session['activate_signature'] = self._extract_parameter(body, 'signature')

        self.log.info('Method=_auth_activate, Challenge=%s, Server Signature=%s' % (session['challenge'], session['activate_signature']))

    def _auth_validate(self, session):
        cms_envelope = base64.b64encode(cms.envelope(session['challenge'],
                                                     session['certificate'],
                                                     session['signature'])).decode('utf-8')

        self.log.info('Method=_auth_validate, Message=CMS Envelope Built, CMS=%s' % cms_envelope)

        auth_validate_request_signature_raw = '%s%s' % (self.smime_header, cms_envelope)
        auth_validate_request_signature_encoded = base64.b64encode(auth_validate_request_signature_raw.encode('utf-8'))

        auth_validate_template = Template(self.auth_validate_template)
        auth_validate_body = auth_validate_template.render(uid = session['uid'],
                                                           device_id = self.device_id,
                                                           ip = self.ip_address,
                                                           session_id = session['id'],
                                                           challenge = session['challenge'],
                                                           signature = session['activate_signature'],
                                                           response = auth_validate_request_signature_encoded.decode('utf-8'))

        self.log.info('Method=_auth_validate, Message=Validate Request Prepared, Request=%s' % auth_validate_body)

        auth_validate_response = requests.post('%s/login/authvalidate' % self.auth_uri,
                                               verify=False,
                                               headers={'User-Agent': self.user_agent,
                                                        'Analytics': json.dumps(session['analytics'])},
                                               data=auth_validate_body)

        body = auth_validate_response.content.decode('utf-8')

        self.log.info('Method=_auth_validate, Message=Validate Response Received, Status=%s, Body=%s' % (auth_validate_response.status_code, body))

        self._parse_validate_response(body, session)

    def _role_select(self, session):
        if (len(session['roles']) > 0):
            uri = self.role_select_uri

            requests.get(uri,
                         verify=False,
                         headers={'User-Agent': self.user_agent,
                                  'Analytics': json.dumps(session['analytics'])},
                         params={'token': session['sso_ticket'],
                                 'selectedRoleUid': session['roles'][0]['id'],
                                 'ssbMode': 0,
                                 'fallbackStatus': 0,
                                 'gacVersion': self.gac_version})

    def _parse_validate_response(self, auth_validate_response, session):
        session['roles'] = []

        session['sso_ticket'] = re.findall('(?:sso_ticket\">)([^<]*)', auth_validate_response)[0]
        session['cn'] = re.findall('(?:cn\">)([^<]*)', auth_validate_response)[0]
        session['sso_logout_url'] = re.findall('(?:sso_logout_url\">)([^<]*)', auth_validate_response)[0]

        for l in auth_validate_response.split('\n'):
            if 'name="nhsjobrole' in l:
                session['roles'].append(self._extract_role(l))

    def _extract_parameter(self, body, parameter_name):
        return re.findall('(?:%s\">)([a-z,A-Z,0-9,/+=]*)' % parameter_name, body)[0]

    def _extract_role(self, role_line):
        ret = {}
        ret['org_code'] = re.findall('(?:orgcode=\")([^\"]*)', role_line)[0]
        role_string = re.findall('(?:>)([^<]*)', role_line)[0]

        role_parts_a = role_string.split(',')
        role_parts_b = role_parts_a[1].split(':')
        ret['org_name'] = role_parts_a[0]
        ret['name'] = role_parts_b[2].strip('"')
        ret['type'] = role_parts_b[0].strip('"')
        ret['sub_type'] = role_parts_b[1].strip('"')
        ret['id'] = re.findall('(?:id=\")([^\"]*)', role_line)[0]
        return ret


