from __future__ import print_function

from PyKCS11 import *
import binascii
import base64

import requests
import re
import pyasn1

class authenticator:
    def __init__(self):
        self.auth_uri = 'http://10.211.55.3:5000'
        self.auth_uri = 'https://gas.nis1.national.ncrs.nhs.uk'

        self.user_agent = 'Mozilla/4.0(compatible;IE;GACv10. 0. 0. 1)'
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
        <gpPARAM name="log_session_id">ZtBJb9tU7T</gpPARAM>
        <gpPARAM name="device_id">b02edd24,ClientIP=172.20.16.255</gpPARAM>
        <gpPARAM name="service">ACTIVATION</gpPARAM>
        </gpOBJECT>"""
        self.auth_validate_template = """<?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE USER SYSTEM "gpOBJECT.DTD">
        <gpOBJECT>
        <gpPARAM name="auth_method">3</gpPARAM>
        <gpPARAM name="app_url">NHST</gpPARAM>
        <gpPARAM name="log_session_id">Ao9qufl+uA</gpPARAM>
        <gpPARAM name="device_id">b02edd23,ClientIP=10.211.55.3</gpPARAM>
        <gpPARAM name="service">AUTHENTICATION</gpPARAM>
        <gpPARAM name="challenge">...challenge...</gpPARAM>
        <gpPARAM name="signature">...signature...</gpPARAM>
        <gpPARAM name="uid">...uid...</gpPARAM>
        <gpPARAM name="card_type">p11</gpPARAM>
        <gpPARAM name="response" encoding="base64">...response....</gpPARAM>
        <gpPARAM name="mobility">0</gpPARAM>
        </gpOBJECT>"""

    def authenticate(self, passcode):
        self._auth_activate()
        self._sign(passcode)
        validate_response = self._auth_validate()
        validate_params = self._parse_validate_response(validate_response)

        return validate_params

    def _build_asn1(self, challenge, cert, signature):
        from pyasn1.type import univ, char, tag
        from pyasn1.codec.ber import encoder, decoder

        outer = univ.Sequence()
        outer[0] = univ.ObjectIdentifier('1.2.840.113549.1.7.2')
        outer[1] = univ.Set() # Needs to be A0
        outer[1][0] = univ.Sequence()
        outer[1][0][0] = univ.Integer(1)
        outer[1][0][1] = univ.Set()
        outer[1][0][1][0] = univ.Sequence()
        outer[1][0][1][0][0] = univ.ObjectIdentifier('1.3.14.3.2.26')
        outer[1][0][1][0][1] = univ.Null()
        outer[1][0][2] = univ.Sequence()
        outer[1][0][2][0] = univ.ObjectIdentifier('1.2.840.113549.1.7.1')
        outer[1][0][2][1] = univ.Set() # Needs to be A0
        outer[1][0][2][1][0] = univ.OctetString(base64.b64decode(challenge))
        outer[1][0][3] = univ.Set() # Needs to be A0

        cert_structure = decoder.decode(cert)

        outer[1][0][3][0] = cert_structure[0]


        outer[1][0][4] = univ.Set()
        outer[1][0][4][0] = univ.Sequence()
        outer[1][0][4][0][0] = univ.Integer(1)

        outer[1][0][4][0][1] = univ.Sequence()
        outer[1][0][4][0][1][0] = cert_structure[0][0][3]
        outer[1][0][4][0][1][1] = cert_structure[0][0][1]

        outer[1][0][4][0][2] = univ.Sequence()
        outer[1][0][4][0][2][0] = univ.ObjectIdentifier('1.3.14.3.2.26')
        outer[1][0][4][0][2][1] = univ.Null()

        outer[1][0][4][0][3] = univ.Sequence()
        outer[1][0][4][0][3][0] = univ.ObjectIdentifier('1.2.840.113549.1.1.1')
        outer[1][0][4][0][3][1] = univ.Null()

        outer[1][0][4][0][4] = univ.OctetString(signature)

        encoded = encoder.encode(outer)

        arr = list(encoded)

        arr[15] = 160
        arr[104] = 160
        arr[52] = 160

        encoded = bytes(arr)

        b64 = base64.b64encode(encoded).decode('utf-8')

        return encoded


    def _auth_activate(self):
        auth_activate = requests.post('%s/login/authactivate' % self.auth_uri,
                                      verify=False,
                                      data=self.auth_activate_template,
                                      headers={'User-Agent': self.user_agent})

        body = auth_activate.content.decode('utf-8')

        self.challenge = self._extract_parameter(body, 'challenge')
        self.activate_signature = self._extract_parameter(body, 'signature')


    def _sign(self, passcode):
        pkcs11 = PyKCS11Lib()
        pkcs11.load('/usr/lib/ClassicClient/libgclib.so')  # define environment variable PYKCS11LIB=YourPKCS11Lib

        slots = pkcs11.getSlotList()
        slot = slots[0]

        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        session.login(passcode, CKU_USER)

        private_keys = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY),])

        for private_key in private_keys:
          key_info = private_key.to_dict()
          if len(key_info['CKA_LABEL']) < 46:
            print(key_info['CKA_LABEL'])
            print(key_info['CKA_ID'])
            print(len(key_info['CKA_LABEL']))
            print("")

            keyID = key_info['CKA_ID']

        toSign = base64.b64decode(self.challenge)

        card_objects = session.findObjects([(CKA_CLASS, CKO_CERTIFICATE), (CKA_ID, keyID)])

        print(session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, keyID)]))

        self.certificate = bytes(card_objects[0].to_dict()['CKA_VALUE'])
        label = card_objects[0].to_dict()['CKA_LABEL'].decode('utf-8')
        self.uid = re.findall('(?:CN=)(.*)', label)[0]

        privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, keyID)])[0]

        self.signature = session.sign(privKey, toSign, Mechanism(CKM_SHA1_RSA_PKCS, None))
        pubKey = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_ID, keyID)])[0]
        result = session.verify(pubKey, toSign, self.signature, Mechanism(CKM_SHA1_RSA_PKCS, None))

        session.logout()
        session.closeSession()

    def _auth_validate(self):
        new_asn1 = base64.b64encode(self._build_asn1(self.challenge, self.certificate, self.signature)).decode('utf-8')

        auth_validate_request_signature_raw = '%s%s' % (self.smime_header, new_asn1)
        auth_validate_request_signature_encoded = base64.b64encode(auth_validate_request_signature_raw.encode('utf-8'))

        auth_validate_request = self.auth_validate_template.replace('...challenge...', self.challenge)
        auth_validate_request = auth_validate_request.replace('...signature...', self.activate_signature)
        auth_validate_request = auth_validate_request.replace('...response...', auth_validate_request_signature_encoded.decode('utf-8'))
        auth_validate_request = auth_validate_request.replace('...uid...', self.uid)

        print(auth_validate_request)

        auth_validate_response = requests.post('%s/login/authvalidate' % self.auth_uri,
                                               verify=False,
                                               headers={'User-Agent': self.user_agent},
                                               data=auth_validate_request)

        body = auth_validate_response.content.decode('utf-8')

        return body


    def _parse_validate_response(self, auth_validate_response):
        ret = {'roles': []}

        ret['sso_ticket'] = re.findall('(?:sso_ticket\">)([^<]*)', auth_validate_response)[0]
        ret['cn'] = re.findall('(?:cn\">)([^<]*)', auth_validate_response)[0]
        ret['sso_logout_url'] = re.findall('(?:sso_logout_url\">)([^<]*)', auth_validate_response)[0]

        for l in auth_validate_response.split('\n'):
            if 'name="nhsjobrole' in l:
                ret['roles'].append(self._extract_role(l))

        return ret


    def _extract_parameter(self, body, parameter_name):
        return re.findall('(?:%s\">)([a-z,A-Z,0-9,/+=]*)' % parameter_name, body)[0]

    def _extract_role(self, role_line):
        ret = {}
        ret['org_code'] = re.findall('(?:orgcode=\")([a-z,A-Z,0-9,/+=]*)', role_line)[0]
        role_string = re.findall('(?:orgcode=\"\w*\">)([^<]*)', role_line)[0]

        role_parts_a = role_string.split(',')
        role_parts_b = role_parts_a[1].split(':')
        ret['org_name'] = role_parts_a[0]
        ret['name'] = role_parts_b[2].strip('"')
        ret['type'] = role_parts_b[0].strip('"')
        ret['sub_type'] = role_parts_b[1].strip('"')
        ret['id'] = re.findall('(?:id=\")([a-z,A-Z,0-9,/+=]*)', role_line)[0]
        return ret



