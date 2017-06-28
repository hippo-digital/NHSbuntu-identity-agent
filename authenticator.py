from __future__ import print_function

from PyKCS11 import *
import binascii
import base64

import requests
import re

class authenticator:
    def __init__(self):
        self.auth_uri = 'http://10.211.55.3:5000'
        self.auth_uri = 'https://gas.nis1.national.ncrs.nhs.uk'
        self.asn1_template = """MIIEuAYJKoZIhvcNAQcCoIIEqTCCBKUCAQExCzAJBgUrDgMCGgUAMD8GCSqGSIb3DQEHAaAyBDBm
        YjFjNWI1NzFhYWIzYzI3NTRmZTRkNDk3M2I3MjA5M2Q2MGMzY2M1OTQ1MzZjNzKgggNzMIIDbzCC
        AlegAwIBAgIEVzHBnDANBgkqhkiG9w0BAQUFADAtMQwwCgYDVQQKEwNuaHMxCzAJBgNVBAsTAkNB
        MRAwDgYDVQQDEwdTdWJDQTAyMB4XDTE2MTEyMjE2MTgxOVoXDTE4MTEyMjE2NDgxOVowNjEMMAoG
        A1UEChMDbmhzMQ8wDQYDVQQLEwZwZW9wbGUxFTATBgNVBAMTDDEwMjA0ODg0Mzk4MzCBnzANBgkq
        hkiG9w0BAQEFAAOBjQAwgYkCgYEAp/9RZ9baYvAj/LnBy8TaQeUrDJYYK7bbXj8l9IijmHbb+icA
        jbb0qkof+lrcqYLHShh5oUdStOO5i+u38VTsCaoZu6cwMls/XO2peJMJFFnwfLL9FIvGtC5Kg9p6
        5jAX0YvE/qlT4seeGQK7q6Nax1NrtUStX05n7cUuiu7Ji/cCAwEAAaOCARAwggEMMAsGA1UdDwQE
        AwIHgDAYBgNVHSAEETAPMA0GCyqGOgCJe2UAAwEBMFAGA1UdHwRJMEcwRaBDoEGkPzA9MQwwCgYD
        VQQKEwNuaHMxCzAJBgNVBAsTAkNBMRAwDgYDVQQDEwdTdWJDQTAyMQ4wDAYDVQQDEwVDUkw1NzAr
        BgNVHRAEJDAigA8yMDE2MTEyMjE2MTgxOVqBDzIwMTgxMTIyMTY0ODE5WjAfBgNVHSMEGDAWgBQS
        Soi3gsCYCcPcpsZpewnlLvD2BTAdBgNVHQ4EFgQUlQvtlbbgKoJmZVE2FszB4wJWP70wCQYDVR0T
        BAIwADAZBgkqhkiG9n0HQQAEDDAKGwRWOC4xAwIEsDANBgkqhkiG9w0BAQUFAAOCAQEAbEGtl/aH
        jbafhCyq7gSLq++wN5eCMvxBVZ8cbXR1qWDBr0EBkmq7AUr19HtR5OG+lCTA/uRcAMDqvKp4GgRd
        0MmdjwfJzqwZH2ztLcg9zqw1t4nfRUwa1kN1aXSNlgw59iBYqDr4w0MVY8ioGZyoIT6S6/DVgH32
        HLpKo1hkKXJSvd8H2R20FBdTR5D03Ka8yfIRftIsH74C5Ikl3Zaz58ifmLSUUdEjnRufKyf1OZ5R
        TzTub+ubD1C5Mdx2RB2zPbt3pR16YK3OXTnPMsbIaO9NKHrbZSqbHALsC7nBhEY4ipxr8UjFg2Zc
        EDPvdIQiHj+Z4U2xGn3kJ7Gmo91STTGB2jCB1wIBATA1MC0xDDAKBgNVBAoTA25oczELMAkGA1UE
        CxMCQ0ExEDAOBgNVBAMTB1N1YkNBMDICBFcxwZwwCQYFKw4DAhoFADANBgkqhkiG9w0BAQEFAASB
        gAbgiKgS9PTha28dW1Ll4UhSpAUAgOAkODAWhTyqhIEMg6PSJ3P6K4f1/0bTBMDmdNvVlvFnAQdc
        yqnqd4/IbZHVIdvriNCe+gYJDc717cKaXoRcIVNj89FU0irluXuu/QDqJE3hCpmVeVnA0d0Gqjab
        fe4adyyaTERYoUckKslF"""
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
        <gpPARAM name="uid">102048843983</gpPARAM>
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

    def _auth_activate(self):
        auth_activate = requests.post('%s/login/authactivate' % self.auth_uri,
                                      verify=False,
                                      data=self.auth_activate_template,
                                      headers={'User-Agent': 'Mozilla/4.0(compatible;IE;GACv7. 2. 2. 21)'})

        body = auth_activate.content.decode('utf-8')
        print(body)



        # self.challenge = re.findall('(?:challenge\">)([a-z,A-Z,0-9,/+=]*)', body)[0]
        self.challenge = self._extract_parameter(body, 'challenge')
        # self.activate_signature = re.findall('(?:signature\">)([a-z,A-Z,0-9,/+=]*)', body)[0]
        self.activate_signature = self._extract_parameter(body, 'signature')

        print('Received challenge=%s' % self.challenge)


    def _sign(self, passcode):
        pkcs11 = PyKCS11Lib()
        pkcs11.load('/usr/lib/ClassicClient/libgclib.so')  # define environment variable PYKCS11LIB=YourPKCS11Lib

        # get 3rd slot
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

        toSign = base64.b64decode(self.challenge) #'fb1c5b571aab3c2754fe4d4973b72093d60c3cc594536c72'

        print(len(toSign))

        print(''.join(format(x, '02x') for x in toSign))

        bytearr = []

        for b in toSign:
          bytearr.append(b) #int(format(b, '0')))

        # find private key and compute signature
        print(session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, keyID)]))

        privKey = session.findObjects([(CKA_CLASS, CKO_PRIVATE_KEY), (CKA_ID, keyID)])[0]

        self.signature = session.sign(privKey, toSign, Mechanism(CKM_SHA1_RSA_PKCS, None))
        print("\nsignature: %s" % binascii.hexlify(bytearray(self.signature)))

        print(len(self.signature))

        # find public key and verify signature
        pubKey = session.findObjects([(CKA_CLASS, CKO_PUBLIC_KEY), (CKA_ID, keyID)])[0]
        result = session.verify(pubKey, toSign, self.signature, Mechanism(CKM_SHA1_RSA_PKCS, None))
        print("\nVerified: %s" % result)

        # logout
        session.logout()
        session.closeSession()

    def _auth_validate(self):
        asn1 = self.asn1_template

        asn1l = list(base64.b64decode(asn1))
        challengel = list(base64.b64decode(self.challenge))

        for n in range(0, len(challengel)):
          asn1l[56 + n] = challengel[n]

        for n in range(0, len(self.signature)):
          asn1l[1084 + n] = self.signature[n]

        asn1b = base64.b64encode(bytes(asn1l)).decode('utf-8')

        auth_validate_request_signature_raw = '%s%s' % (self.smime_header, asn1b)
        auth_validate_request_signature_encoded = base64.b64encode(auth_validate_request_signature_raw.encode('utf-8'))

        auth_validate_request = self.auth_validate_template.replace('...challenge...', self.challenge)
        auth_validate_request = auth_validate_request.replace('...signature...', self.activate_signature)
        auth_validate_request = auth_validate_request.replace('...response...', auth_validate_request_signature_encoded.decode('utf-8'))

        print(auth_validate_request)

        auth_validate_response = requests.post('%s/login/authvalidate' % self.auth_uri,
                                               verify=False,
                                               headers={'User-Agent': 'Mozilla/4.0(compatible;IE;GACv7. 2. 2. 21)'},
                                               data=auth_validate_request)

        body = auth_validate_response.content.decode('utf-8')
        print(body)

        return body


    def _parse_validate_response(self, auth_validate_response):
        ret = {'roles': []}

        ret['sso_ticket'] = self._extract_parameter(auth_validate_response, 'sso_ticket')
        ret['cn'] = self._extract_parameter(auth_validate_response, 'cn')
        ret['sso_logout_url'] = self._extract_parameter(auth_validate_response, 'sso_logout_url')

        for l in auth_validate_response.split('\n'):
            if 'name="nhsjobrole' in l:
                ret['roles'].append(self._extract_role(l))



    def _extract_parameter(self, body, parameter_name):
        return re.findall('(?:%s\">)([a-z,A-Z,0-9,/+=]*)' % parameter_name, body)[0]

    def _extract_role(self, role_line):
        ret = {}
        org_code = re.findall('(?:orgcode=\")([a-z,A-Z,0-9,/+=]*)', role_line)[0]
        role_id = self._extract_parameter(role_line, 'id')
        return {}



